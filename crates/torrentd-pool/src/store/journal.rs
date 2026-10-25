//! The mutation journal: plans, the steps written before each runs, and
//! the conditional status changes that keep two applies off one plan.

use rusqlite::params;
use rusqlite::OptionalExtension;

use super::PlanDelete;
use super::PoolStore;
use crate::model::PlanRow;
use crate::model::PlanStep;
use crate::model::PlanStepRow;
use crate::model::PoolError;

impl PoolStore {
    pub fn create_plan(&self, kind: &str, spec: &str, created_at: i64) -> Result<i64, PoolError> {
        self.conn.execute(
            "INSERT INTO plan(kind, created_at, status, spec) VALUES (?1,?2,'draft',?3)",
            params![kind, created_at, spec],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn add_plan_steps(&mut self, plan_id: i64, steps: &[PlanStep]) -> Result<(), PoolError> {
        let tx = self.conn.savepoint()?;
        {
            let mut ins = tx.prepare(
                "INSERT INTO plan_step(plan_id, seq, op, src, dst, status, error)
                 VALUES (?1,?2,?3,?4,?5,'pending',NULL)",
            )?;
            for (i, st) in steps.iter().enumerate() {
                ins.execute(params![plan_id, i as i64, st.op, st.src, st.dst])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn plan(&self, id: i64) -> Result<Option<PlanRow>, PoolError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, kind, created_at, applied_at, status, spec FROM plan WHERE id = ?1",
                params![id],
                |r| {
                    Ok(PlanRow {
                        id: r.get(0)?,
                        kind: r.get(1)?,
                        created_at: r.get(2)?,
                        applied_at: r.get(3)?,
                        status: r.get(4)?,
                        spec: r.get(5)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn plans(&self) -> Result<Vec<PlanRow>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, created_at, applied_at, status, spec FROM plan ORDER BY id DESC",
        )?;
        let rows = st.query_map([], |r| {
            Ok(PlanRow {
                id: r.get(0)?,
                kind: r.get(1)?,
                created_at: r.get(2)?,
                applied_at: r.get(3)?,
                status: r.get(4)?,
                spec: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Plans left mid-apply by a crash or a kill, in id order so the oldest is
    /// resumed first.
    pub fn unfinished_plans(&self) -> Result<Vec<PlanRow>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, created_at, applied_at, status, spec
             FROM plan WHERE status = 'applying' ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok(PlanRow {
                id: r.get(0)?,
                kind: r.get(1)?,
                created_at: r.get(2)?,
                applied_at: r.get(3)?,
                status: r.get(4)?,
                spec: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn set_plan_status(
        &self,
        id: i64,
        status: &str,
        applied_at: Option<i64>,
    ) -> Result<(), PoolError> {
        self.conn.execute(
            "UPDATE plan SET status = ?2, applied_at = COALESCE(?3, applied_at) WHERE id = ?1",
            params![id, status, applied_at],
        )?;
        Ok(())
    }

    /// Atomically take ownership of a plan for applying.
    ///
    /// Returns `true` if this caller now owns it. Two concurrent
    /// `POST /v1/pool/plans/{plan_id}/apply` requests otherwise both read the steps
    /// as `pending` and both execute them — the second racing the first over
    /// the same files. A conditional `UPDATE` in one statement makes exactly
    /// one of them win.
    ///
    /// `resume` additionally admits a plan already in `applying`, which is
    /// what a crash leaves behind. Only the startup re-drive passes it: for an
    /// API request `applying` means another caller is mid-apply right now, and
    /// admitting it would be the very race this exists to prevent.
    pub fn claim_plan_for_apply(&self, id: i64, resume: bool) -> Result<bool, PoolError> {
        use crate::model::plan_status as ps;
        let changed = if resume {
            self.conn.execute(
                "UPDATE plan SET status = ?2 WHERE id = ?1 AND status IN (?3, ?4, ?5)",
                params![id, ps::APPLYING, ps::DRAFT, ps::FAILED, ps::APPLYING],
            )?
        } else {
            self.conn.execute(
                "UPDATE plan SET status = ?2 WHERE id = ?1 AND status IN (?3, ?4)",
                params![id, ps::APPLYING, ps::DRAFT, ps::FAILED],
            )?
        };
        Ok(changed == 1)
    }

    /// Park a plan an apply refused before claiming it in `failed`, where an
    /// operator can apply it again or discard it.
    ///
    /// Conditional on the plan being one this caller could have claimed —
    /// `draft` or `failed`, and with `resume` also `applying` — exactly as
    /// [`Self::claim_plan_for_apply`] is. An API apply that finds a step
    /// `in_progress` because another apply is running that step right now
    /// must not flip the running plan to `failed`: `failed` is claimable, so a
    /// third apply would then run the same steps alongside the first. Returns
    /// whether the plan was parked; `false` means it is no longer this
    /// caller's to touch.
    pub fn fail_unclaimed_plan(&self, id: i64, resume: bool) -> Result<bool, PoolError> {
        use crate::model::plan_status as ps;
        let changed = if resume {
            self.conn.execute(
                "UPDATE plan SET status = ?2 WHERE id = ?1 AND status IN (?3, ?4, ?5)",
                params![id, ps::FAILED, ps::DRAFT, ps::FAILED, ps::APPLYING],
            )?
        } else {
            self.conn.execute(
                "UPDATE plan SET status = ?2 WHERE id = ?1 AND status IN (?3, ?4)",
                params![id, ps::FAILED, ps::DRAFT, ps::FAILED],
            )?
        };
        Ok(changed == 1)
    }

    /// Discard a plan and its steps, unless it is mid-apply.
    ///
    /// The status test is part of the `DELETE` itself, so no apply can claim
    /// the plan between the test and the delete: a plan read as `draft` and
    /// then deleted after an apply claimed it lost its step journal while the
    /// apply went on moving files. One transaction for the plan and its
    /// steps, so a process dying between the two leaves no orphaned
    /// `plan_step` rows.
    pub fn delete_plan(&mut self, id: i64) -> Result<PlanDelete, PoolError> {
        use crate::model::plan_status as ps;
        let tx = self.conn.savepoint()?;
        let deleted = tx.execute(
            "DELETE FROM plan WHERE id = ?1 AND status <> ?2",
            params![id, ps::APPLYING],
        )?;
        let outcome = if deleted == 1 {
            tx.execute("DELETE FROM plan_step WHERE plan_id = ?1", params![id])?;
            PlanDelete::Deleted
        } else {
            let exists: bool = tx.query_row(
                "SELECT EXISTS (SELECT 1 FROM plan WHERE id = ?1)",
                params![id],
                |r| r.get(0),
            )?;
            if exists {
                PlanDelete::Applying
            } else {
                PlanDelete::NotFound
            }
        };
        tx.commit()?;
        Ok(outcome)
    }

    pub fn plan_steps(&self, plan_id: i64) -> Result<Vec<PlanStepRow>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT seq, op, src, dst, status, error FROM plan_step
             WHERE plan_id = ?1 ORDER BY seq",
        )?;
        let rows = st.query_map(params![plan_id], |r| {
            Ok(PlanStepRow {
                seq: r.get(0)?,
                op: r.get(1)?,
                src: r.get(2)?,
                dst: r.get(3)?,
                status: r.get(4)?,
                error: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Up to `limit` steps of `plan_id` after `after_seq` (from the first
    /// when `None`), in `seq` order: one page, read off the primary key
    /// whatever the plan's size.
    pub fn plan_steps_page(
        &self,
        plan_id: i64,
        after_seq: Option<i64>,
        limit: usize,
    ) -> Result<Vec<PlanStepRow>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT seq, op, src, dst, status, error FROM plan_step
             WHERE plan_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
        )?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = st.query_map(params![plan_id, after_seq.unwrap_or(-1), limit], |r| {
            Ok(PlanStepRow {
                seq: r.get(0)?,
                op: r.get(1)?,
                src: r.get(2)?,
                dst: r.get(3)?,
                status: r.get(4)?,
                error: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// How many of `plan_id`'s steps stand in each status, as `(status,
    /// count)` pairs in status order. A status no step holds is absent.
    pub fn plan_step_counts(&self, plan_id: i64) -> Result<Vec<(String, u64)>, PoolError> {
        let mut st = self.conn.prepare(
            "SELECT status, count(*) FROM plan_step WHERE plan_id = ?1
             GROUP BY status ORDER BY status",
        )?;
        let rows = st.query_map(params![plan_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, u64>(1)?))
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn set_step_status(
        &self,
        plan_id: i64,
        seq: i64,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), PoolError> {
        self.conn.execute(
            "UPDATE plan_step SET status = ?3, error = ?4 WHERE plan_id = ?1 AND seq = ?2",
            params![plan_id, seq, status, error],
        )?;
        Ok(())
    }

    /// Set the status and error of several of `plan_id`'s steps, each
    /// `(seq, status, error)`, in one transaction: one commit, so one WAL
    /// fsync, however many steps it records. Either every row is written or
    /// none is.
    pub fn set_steps_status(
        &mut self,
        plan_id: i64,
        steps: &[(i64, &str, Option<&str>)],
    ) -> Result<(), PoolError> {
        let tx = self.conn.savepoint()?;
        {
            let mut up = tx.prepare(
                "UPDATE plan_step SET status = ?3, error = ?4 WHERE plan_id = ?1 AND seq = ?2",
            )?;
            for (seq, status, error) in steps {
                up.execute(params![plan_id, seq, status, error])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}
