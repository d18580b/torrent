//! What lets one `POST /v1/pool/adoptions` adopt a thousand torrents without
//! waiting on a thousand disk flushes in turn.
//!
//! A target's time goes mostly to waiting on the disk: a fast-path add
//! writes its `.torrent` and save path durably, and every adopted torrent's
//! pool index records are a commit, which waits on its own fsync since the
//! index is `synchronous=FULL`. One target at a time, a request waited on
//! every one of those flushes in turn (issue #507: ~145 ms a torrent on a
//! slow volume). [`in_parallel`] works on several targets at once, so one
//! target's flush overlaps another's, and [`GroupCommit`] lets the index
//! records of the targets in flight share one commit, since the index
//! writer takes one commit at a time.

use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::mpsc;

use parking_lot::Mutex;
use torrentd_pool::PoolError;
use torrentd_pool::PoolStore;

/// How many of one adoption's targets are worked on at once.
pub(crate) const ADOPT_WORKERS: usize = 8;

/// `f` over every target, [`ADOPT_WORKERS`] at a time, its results in the
/// targets' order.
///
/// `key` names what a target acts on: every target with one key goes to the
/// same worker, in the order given, so a target repeated in one request meets
/// what its earlier occurrence did, exactly as it did one target at a time —
/// the claim it already holds, or the adoption it already recorded. Targets
/// with distinct keys share nothing an adoption writes. The caller's span
/// goes with every worker, so what a target logs is the request's.
pub(crate) fn in_parallel<I: Sync, T: Send>(
    targets: &[I],
    key: impl Fn(&I) -> &str,
    f: impl Fn(&I) -> T + Sync,
) -> Vec<T> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    let mut group_of = HashMap::new();
    for (i, target) in targets.iter().enumerate() {
        let g = *group_of.entry(key(target)).or_insert_with(|| {
            groups.push(Vec::new());
            groups.len() - 1
        });
        groups[g].push(i);
    }
    let results: Vec<Mutex<Option<T>>> = targets.iter().map(|_| Mutex::new(None)).collect();
    let work = |group: &[usize]| {
        for &i in group {
            *results[i].lock() = Some(f(&targets[i]));
        }
    };
    let workers = ADOPT_WORKERS.min(groups.len());
    if workers <= 1 {
        groups.iter().for_each(|g| work(g));
    } else {
        let next = AtomicUsize::new(0);
        let span = tracing::Span::current();
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    let _entered = span.enter();
                    while let Some(group) = groups.get(next.fetch_add(1, Ordering::Relaxed)) {
                        work(group);
                    }
                });
            }
        });
    }
    results
        .into_iter()
        .map(|r| {
            r.into_inner()
                .expect("every target is in a group, and every group is worked")
        })
        .collect()
}

/// What one job's closure returned, whatever its type.
type Value = Box<dyn Any + Send>;

/// What one job's writes came to.
type Done = Result<Value, String>;

/// Index writes waiting to be committed.
struct Job {
    run: Box<dyn FnOnce(&mut PoolStore) -> Value + Send>,
    done: mpsc::SyncSender<Done>,
}

/// Index writes from several threads, committed together.
///
/// A caller queues its writes and then takes the writer; whoever takes it
/// runs every job queued by then, its own and the others', in one
/// transaction, and hands each its result before letting go of the writer.
/// Each caller still returns only once its own writes are committed, or
/// known lost, so what it does next happens after them exactly as it did
/// when each wrote alone. A caller alone in the queue commits alone.
#[derive(Default)]
pub(crate) struct GroupCommit {
    queue: Mutex<Vec<Job>>,
}

impl GroupCommit {
    /// Run `f` on the writer `lock` hands out, in a transaction shared with
    /// whatever else is queued, and return what it returned once that
    /// transaction committed.
    ///
    /// `Err` is the transaction's failure to begin or commit, after which
    /// none of `f`'s writes are in the index. A failed statement inside `f`
    /// is `f`'s own to report: it fails that statement and no other job's,
    /// unless SQLite rolled back the whole transaction for it, which fails
    /// the group with `Err`. So `f` checks
    /// [`PoolStore::in_open_transaction`] before each write after its first,
    /// or that write would autocommit while `Err` says it never landed.
    pub(crate) fn run<T, G>(
        &self,
        lock: impl FnOnce() -> G,
        f: impl FnOnce(&mut PoolStore) -> T + Send + 'static,
    ) -> Result<T, String>
    where
        T: Send + 'static,
        G: std::ops::DerefMut<Target = PoolStore>,
    {
        let (done, result) = mpsc::sync_channel(1);
        self.queue.lock().push(Job {
            run: Box::new(move |store| Box::new(f(store)) as Value),
            done,
        });
        {
            let mut store = lock();
            let jobs = std::mem::take(&mut *self.queue.lock());
            if !jobs.is_empty() {
                commit_all(&mut store, jobs);
            }
        }
        // Queued before the writer was taken, so whoever held it first took
        // this job, ran it, and answered it before letting go.
        result
            .recv()
            .expect("a queued job is answered before the writer is released")
            .map(|value| {
                *value
                    .downcast::<T>()
                    .expect("a job answers with what its own closure returned")
            })
    }
}

/// Why a group's transaction did not commit.
struct Failed(String);

impl From<PoolError> for Failed {
    fn from(e: PoolError) -> Self {
        Failed(e.to_string())
    }
}

/// Run `jobs` in one transaction and answer each.
///
/// A job's statement can make SQLite roll back the whole transaction
/// (`SQLITE_FULL`, `SQLITE_IOERR`, `SQLITE_NOMEM`), and every statement
/// after it would then autocommit. So no job runs once the transaction is
/// gone, and the group fails: the jobs that ran were rolled back with it.
fn commit_all(store: &mut PoolStore, jobs: Vec<Job>) {
    let mut ran = Vec::with_capacity(jobs.len());
    let mut jobs = jobs.into_iter();
    let committed = store.in_transaction(|st| {
        for job in jobs.by_ref() {
            ran.push(((job.run)(st), job.done));
            if !st.in_open_transaction() {
                return Err(Failed(
                    "a failed statement rolled back the shared transaction".to_owned(),
                ));
            }
        }
        Ok::<_, Failed>(())
    });
    match committed {
        Ok(()) => {
            for (value, done) in ran {
                let _ = done.send(Ok(value));
            }
        }
        Err(Failed(why)) => {
            // What ran was rolled back with the rest; what did not run, the
            // transaction never began for or was gone before.
            for done in ran.into_iter().map(|(_, d)| d).chain(jobs.map(|j| j.done)) {
                let _ = done.send(Err(why.clone()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::Barrier;

    use super::*;

    /// Results come back in the targets' order, every occurrence of one key
    /// runs on one worker in the order given, and more than one worker runs.
    #[test]
    fn in_parallel_keeps_order_and_runs_one_key_in_turn() {
        let targets: Vec<String> = (0..40).map(|i| format!("k{}", i % 10)).collect();
        let seen = Mutex::new(HashMap::<String, Vec<(usize, std::thread::ThreadId)>>::new());
        let next = AtomicUsize::new(0);
        let threads = Mutex::new(std::collections::HashSet::new());
        let out = in_parallel(&targets, String::as_str, |t| {
            let n = next.fetch_add(1, Ordering::SeqCst);
            let me = std::thread::current().id();
            threads.lock().insert(me);
            seen.lock().entry(t.clone()).or_default().push((n, me));
            // Long enough that one worker cannot take every group.
            std::thread::sleep(std::time::Duration::from_millis(2));
            format!("{t}!")
        });
        let want: Vec<String> = targets.iter().map(|t| format!("{t}!")).collect();
        assert_eq!(out, want);
        for (key, runs) in seen.into_inner() {
            assert_eq!(runs.len(), 4, "{key}");
            assert!(runs.windows(2).all(|w| w[0].0 < w[1].0), "{key}: {runs:?}");
            assert!(runs.iter().all(|r| r.1 == runs[0].1), "{key}: {runs:?}");
        }
        assert!(threads.into_inner().len() > 1);
    }

    /// One target, or one key, runs on the caller's own thread.
    #[test]
    fn in_parallel_runs_a_single_key_inline() {
        let me = std::thread::current().id();
        let out = in_parallel(&["a", "a"], |t| t, |_| std::thread::current().id());
        assert_eq!(out, vec![me, me]);
    }

    fn store() -> (tempfile::TempDir, Arc<Mutex<PoolStore>>) {
        let dir = tempfile::tempdir().unwrap();
        let store = PoolStore::open(&dir.path().join("pool.db")).unwrap();
        (dir, Arc::new(Mutex::new(store)))
    }

    /// Jobs queued while the writer is held commit together, in one
    /// transaction, when it is released; each caller gets its own result,
    /// and a statement that fails in one job fails only that job.
    #[test]
    fn jobs_queued_behind_the_writer_commit_together() {
        let (_dir, store) = store();
        let commits = store.lock().count_commits();
        let group = Arc::new(GroupCommit::default());
        let held = store.lock();
        let callers = 5;
        let ready = Arc::new(Barrier::new(callers + 1));
        let handles: Vec<_> = (0..callers)
            .map(|i| {
                let (store, group, ready) = (store.clone(), group.clone(), ready.clone());
                std::thread::spawn(move || {
                    ready.wait();
                    group.run(
                        || store.lock(),
                        move |st| {
                            if i == 0 {
                                // No such torrent: the foreign key refuses it.
                                return st
                                    .set_adoption(
                                        "00",
                                        torrentd_pool::AdoptionState::Adopted,
                                        None,
                                        None,
                                        None,
                                        None,
                                        None,
                                    )
                                    .map(|()| 0);
                            }
                            st.upsert_root(std::path::Path::new(&format!("/root{i}")))
                        },
                    )
                })
            })
            .collect();
        ready.wait();
        // Every caller is queued behind the held writer before it is let go.
        while group.queue.lock().len() < callers {
            std::thread::yield_now();
        }
        drop(held);
        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().unwrap().expect("the transaction commits"))
            .collect();
        assert!(results[0].is_err(), "{results:?}");
        assert!(results[1..].iter().all(Result::is_ok), "{results:?}");
        assert_eq!(commits.load(Ordering::Relaxed), 1);
        let roots = store.lock().roots().unwrap();
        assert_eq!(roots.len(), callers - 1, "{roots:?}");
    }

    /// Issue #507: an adopt's index records are one commit, and so one
    /// fsync, on either path: the fast path's adoption and owner, and the
    /// verify path's owner and queue row. Each was a commit of its own.
    #[test]
    fn an_adopt_commits_its_index_records_once() {
        use torrentd_engine::ProfileId;

        use crate::pool_service::tests::fast_path_library;
        use crate::profile_registry::test_entry;
        use crate::profile_registry::ProfileRegistry;
        use crate::profile_registry::ProfileStatus;

        let profiles = ProfileRegistry::new(vec![test_entry("p", ProfileStatus::Active)]);
        for complete in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let (pool, ih, _engine, source) = fast_path_library(dir.path());
            if !complete {
                // No piece had: planned as a verify.
                let fr = dir.path().join("library/t.fastresume");
                let mut bytes = std::fs::read(&fr).unwrap();
                let at = bytes.len() - 2;
                bytes[at] = 0;
                std::fs::write(&fr, bytes).unwrap();
                pool.scan().unwrap();
            }
            let commits = pool.with_store(PoolStore::count_commits);
            let adopted = pool
                .adopt(&source, &profiles, &ih, ProfileId::new("p"), false)
                .unwrap_or_else(|e| panic!("{}", e.reason));
            let want = if complete {
                crate::pool_service::Adopted::FastPath
            } else {
                crate::pool_service::Adopted::QueuedForVerification
            };
            assert_eq!(adopted, want);
            assert_eq!(commits.load(Ordering::Relaxed), 1, "{want:?}");
        }
    }

    /// A transaction that cannot begin runs no job, and says so to each:
    /// here another connection holds the database's write lock.
    #[test]
    fn a_transaction_that_cannot_begin_fails_every_job() {
        let (dir, store) = store();
        let mut other = PoolStore::open(&dir.path().join("pool.db")).unwrap();
        let group = GroupCommit::default();
        let got = other
            .in_transaction(|_| {
                Ok::<_, PoolError>(group.run(
                    || store.lock(),
                    |st| st.upsert_root(std::path::Path::new("/r")),
                ))
            })
            .unwrap();
        assert!(got.is_err(), "{got:?}");
        assert!(store.lock().roots().unwrap().is_empty());
    }

    /// A statement that makes SQLite roll back the whole transaction fails
    /// every job in the group, and nothing after it lands as an autocommit:
    /// neither the failing job's own later write nor a later job's. A
    /// `RAISE(ROLLBACK)` trigger stands in for `SQLITE_FULL`/`SQLITE_IOERR`.
    #[test]
    fn a_statement_that_rolls_back_the_transaction_fails_the_group() {
        let (dir, store) = store();
        rusqlite::Connection::open(dir.path().join("pool.db"))
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER boom BEFORE INSERT ON root WHEN NEW.path = '/boom'
                 BEGIN SELECT RAISE(ROLLBACK, 'boom'); END;",
            )
            .unwrap();
        let group = Arc::new(GroupCommit::default());
        let held = store.lock();
        let roots: [&[&str]; 3] = [&["/before"], &["/boom", "/same-job"], &["/after"]];
        let mut handles = Vec::new();
        for (n, paths) in roots.into_iter().enumerate() {
            let (writer, queue) = (store.clone(), group.clone());
            handles.push(std::thread::spawn(move || {
                queue.run(
                    || writer.lock(),
                    move |st| {
                        // As an adopt's job does: a check before each write
                        // after its first.
                        for (i, p) in paths.iter().enumerate() {
                            if i > 0 && !st.in_open_transaction() {
                                break;
                            }
                            let _ = st.upsert_root(std::path::Path::new(p));
                        }
                    },
                )
            }));
            // Queued in this order, so the jobs run in it.
            while group.queue.lock().len() <= n {
                std::thread::yield_now();
            }
        }
        drop(held);
        for h in handles {
            let got = h.join().unwrap();
            assert!(got.is_err(), "{got:?}");
        }
        let roots = store.lock().roots().unwrap();
        assert!(roots.is_empty(), "{roots:?}");
        // The connection is usable again.
        group
            .run(
                || store.lock(),
                |st| st.upsert_root(std::path::Path::new("/r")),
            )
            .unwrap()
            .unwrap();
    }
}
