{{/* Names and labels. */}}
{{- define "torrentd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "torrentd.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "torrentd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "torrentd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "torrentd.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "torrentd.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "torrentd.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if .Values.image.digest -}}
{{- printf "%s:%s@%s" .Values.image.repository $tag .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end -}}

{{- define "torrentd.configSecretName" -}}
{{- .Values.config.existingSecret | default (printf "%s-config" (include "torrentd.fullname" .)) -}}
{{- end -}}

{{/*
Helm reads every number in values as a float64, and toToml writes one as
`10000.0` or `1.048576e+07`, which a u32 key refuses. torrentd's config holds
no fractional number, so a whole float is turned back into an int64 in place,
through nested tables and arrays of tables. Takes a dict it may modify.
*/}}
{{- define "torrentd.intify" -}}
{{- $m := . -}}
{{- range $k, $v := $m -}}
{{- if kindIs "float64" $v -}}
{{- if eq $v (floor $v) -}}{{- $_ := set $m $k (int64 $v) -}}{{- end -}}
{{- else if kindIs "map" $v -}}
{{- include "torrentd.intify" $v -}}
{{- else if kindIs "slice" $v -}}
{{- $out := list -}}
{{- range $e := $v -}}
{{- if and (kindIs "float64" $e) (eq $e (floor $e)) -}}
{{- $out = append $out (int64 $e) -}}
{{- else -}}
{{- if kindIs "map" $e -}}{{- include "torrentd.intify" $e -}}{{- end -}}
{{- $out = append $out $e -}}
{{- end -}}
{{- end -}}
{{- $_ := set $m $k $out -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
The config the chart renders, as a dict: config.settings with the chart's
defaults filled in where a key is absent, and http_listen written from
api.port. Fails the render on a config the daemon would refuse at boot for
a reason the chart can see.
*/}}
{{- define "torrentd.settings" -}}
{{- $s := deepCopy (.Values.config.settings | default dict) -}}
{{- if hasKey $s "http_listen" -}}
{{- fail "config.settings.http_listen is written by the chart from api.port; set api.port instead" -}}
{{- end -}}
{{- $_ := set $s "http_listen" (printf "0.0.0.0:%d" (int .Values.api.port)) -}}
{{- if not (hasKey $s "default_save_path") -}}{{- $_ := set $s "default_save_path" "/data/torrents" -}}{{- end -}}
{{- if not (hasKey $s "resume_dir") -}}{{- $_ := set $s "resume_dir" "/var/lib/torrentd/resume" -}}{{- end -}}
{{- if not (hasKey $s "torrent_dir") -}}{{- $_ := set $s "torrent_dir" "/var/lib/torrentd/torrents" -}}{{- end -}}
{{- if not (hasKey $s "trusted_proxies") -}}{{- $_ := set $s "trusted_proxies" (list .Values.cluster.podCIDR) -}}{{- end -}}
{{- if $s.network_kill_switch -}}
{{- if not (hasKey $s "kill_switch_api_interfaces") -}}{{- $_ := set $s "kill_switch_api_interfaces" (list "eth0") -}}{{- end -}}
{{- if not (hasKey $s "kill_switch_dns_servers") -}}{{- $_ := set $s "kill_switch_dns_servers" (list .Values.cluster.dnsIP) -}}{{- end -}}
{{- end -}}
{{- if not $s.profile -}}
{{- fail "config.settings.profile is empty: torrentd refuses a config with no [[profile]]" -}}
{{- end -}}
{{- if and (not $s.auth) (not $s.allow_unauthenticated) -}}
{{- fail "config.settings needs `auth` (or `allow_unauthenticated: true`): the API listens on the pod's address, and a non-loopback http_listen requires [auth]" -}}
{{- end -}}
{{- toYaml $s -}}
{{- end -}}

{{/* The rendered torrentd.toml. fromYaml reads numbers as float64 again. */}}
{{- define "torrentd.configToml" -}}
{{- $s := include "torrentd.settings" . | fromYaml -}}
{{- include "torrentd.intify" $s -}}
{{- toToml $s -}}
{{- end -}}

{{/* "true" where the pod needs NET_ADMIN, empty otherwise. */}}
{{- define "torrentd.vpn" -}}
{{- $vpn := .Values.vpn.enabled -}}
{{- if not .Values.config.existingSecret -}}
{{- $s := .Values.config.settings | default dict -}}
{{- if $s.network_kill_switch -}}{{- $vpn = true -}}{{- end -}}
{{- range $p := ($s.profile | default list) -}}
{{- if eq (toString $p.network) "vpn" -}}{{- $vpn = true -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- if $vpn -}}true{{- end -}}
{{- end -}}

{{/* shutdown_drain_secs plus the margin, unless set outright. */}}
{{- define "torrentd.terminationGrace" -}}
{{- if kindIs "invalid" .Values.terminationGracePeriodSeconds -}}
{{- $drain := 60 -}}
{{- $s := .Values.config.settings | default dict -}}
{{- if and (not .Values.config.existingSecret) (hasKey $s "shutdown_drain_secs") -}}
{{- $drain = int $s.shutdown_drain_secs -}}
{{- end -}}
{{- add $drain (int .Values.shutdownGraceMarginSeconds) -}}
{{- else -}}
{{- int .Values.terminationGracePeriodSeconds -}}
{{- end -}}
{{- end -}}
