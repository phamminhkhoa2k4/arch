package cleanup

import (
	"fmt"
	"strings"
)

// Build turns a cleanup-eligible component into the six-stage plan.
// Every stage carries an action, a gate condition and the confirmer
// who signs it off; the script body holds the exact commands plus a
// "# rollback:" counterpart for each mutating step.
func Build(c Component) Plan {
	p := Plan{Component: c}
	p.VolumeWarnings = volumeWarnings(c)

	ref := c.Ref
	if ref == "" {
		ref = c.Name
	}

	p.Stages = []Stage{
		{
			Name:      "Candidate",
			Action:    fmt.Sprintf("Đọc toàn bộ kế hoạch này, chạy `archaeologist delete-check %s` và xác nhận verdict vẫn là orphan, không có blocker mới.", ref),
			Gate:      "delete-check trả về LIKELY_ORPHANED hoặc ORPHANED với danh sách blockers rỗng.",
			Confirmer: "Operator tự xác nhận sau khi đọc (plan confirm <component> Candidate).",
			Script:    candidateScript(ref),
		},
		{
			Name:      "Quarantined",
			Action:    quarantineAction(c),
			Gate:      "Sau 7 ngày cách ly: không complain/log/gọi tới mới; chạy lại delete-check vẫn không có blocker.",
			Confirmer: "Operator đối chiếu log + delete-check rồi confirm.",
			Script:    quarantineScript(c),
		},
		{
			Name:      "Observed",
			Action:    "Không làm gì thêm — để observe daemon quan sát 14 ngày sau khi cách ly.",
			Gate:      "Cửa sổ quan sát ≥ 14 ngày, không có activity mới, verdict vẫn orphan.",
			Confirmer: "Re-scan + delete-check (operator).",
			Script:    observedScript(ref),
		},
		{
			Name:      "Archived",
			Action:    archiveAction(c),
			Gate:      "Thư mục archive-<timestamp> đã tồn tại và đầy đủ file; mọi volume dữ liệu đã được backup tay.",
			Confirmer: "Operator xác nhận backup (bao gồm volume) trước khi qua Removed.",
			Script:    archiveScript(c, p.VolumeWarnings),
		},
		{
			Name:      "Removed",
			Action:    removedAction(c),
			Gate:      "delete-check trả về 'không tìm thấy component' trên scan mới.",
			Confirmer: "Operator chạy delete-check sau khi gỡ.",
			Script:    removedScript(c),
		},
		{
			Name:      "Verified",
			Action:    "Chạy `archaeologist scan` mới và `delete-check` lại toàn bộ khu vực: component đã biến mất, không để lại side-effect (route chết, cron lỗi, log lỗi).",
			Gate:      "Scan mới không còn entity này và không có finding mới liên quan.",
			Confirmer: "Operator + kết quả scan mới.",
			Script:    verifiedScript(ref),
		},
	}
	return p
}

// volumeWarnings lists every container volume that must be backed up
// by hand before removal; data volumes are never deleted automatically.
func volumeWarnings(c Component) []string {
	if c.Kind != "container" {
		return nil
	}
	raw := strings.TrimSpace(c.Attrs["volumes"])
	if raw == "" {
		return nil
	}
	var out []string
	for _, v := range strings.Split(raw, ",") {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func candidateScript(ref string) string {
	return strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Candidate — verify the verdict is still safe to act on.",
		fmt.Sprintf("archaeologist delete-check %q --db archaeologist.db", ref),
		"",
		"# rollback: none needed (read-only step)",
	}, "\n") + "\n"
}

func observedScript(ref string) string {
	return strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Observed — wait for the 14-day observation window; no commands.",
		fmt.Sprintf("# After 14 days: archaeologist delete-check %q --db archaeologist.db", ref),
		"",
		"# rollback: none needed (waiting step)",
	}, "\n") + "\n"
}

func quarantineAction(c Component) string {
	switch c.Kind {
	case "systemd_unit", "timer":
		return fmt.Sprintf("Tạm dừng và không cho start cùng boot: `systemctl disable --now %s`.", c.Name)
	case "container":
		return fmt.Sprintf("Dừng container, giữ nguyên image/volume: `docker stop %s`.", c.Name)
	case "cron_job":
		return fmt.Sprintf("Vô hiệu hoá job: di chuyển file cron sang `.disabled` (%s).", attrOr(c.Attrs, "file", "không rõ file"))
	case "nginx_route":
		return "Comment toàn bộ block route trong config nginx (giữ lại file đã backup ở Archived); reload nginx."
	default:
		return fmt.Sprintf("Cách ly %s theo cơ chế của loại này — xem lệnh trong script.", c.Kind)
	}
}

func quarantineScript(c Component) string {
	head := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Quarantined — stop the component without deleting anything.",
	}
	var body []string
	switch c.Kind {
	case "systemd_unit", "timer":
		body = []string{
			fmt.Sprintf("systemctl disable --now %s", c.Name),
			fmt.Sprintf("# rollback: systemctl enable --now %s", c.Name),
		}
	case "container":
		body = []string{
			fmt.Sprintf("docker stop %s", c.Name),
			fmt.Sprintf("# rollback: docker start %s", c.Name),
		}
	case "cron_job":
		f := attrOr(c.Attrs, "file", "")
		if f == "" {
			body = []string{
				fmt.Sprintf("# unknown cron file for %q — edit crontab manually, then re-run", c.Name),
				"# rollback: restore the crontab backup you made",
			}
		} else {
			body = []string{
				fmt.Sprintf("mv %q %q", f, f+".disabled"),
				fmt.Sprintf("# rollback: mv %q %q", f+".disabled", f),
			}
		}
	case "nginx_route":
		body = []string{
			"# Backup the config first (see the Archived stage), then comment out",
			"# the server/location block for this route and reload:",
			fmt.Sprintf("# sed -i.bak 's|^\\s*location %s|# location %s|' /etc/nginx/sites-enabled/*", c.Name, c.Name),
			"nginx -t && systemctl reload nginx",
			"# rollback: restore the .bak file from the Archived copy and reload",
		}
	default:
		body = []string{
			fmt.Sprintf("# no standard quarantine command for kind %q — see the plan document in this directory", c.Kind),
			"# rollback: reverse whatever manual step you take",
		}
	}
	return strings.Join(append(head, append(body, "", "# end quarantine")...), "\n") + "\n"
}

func archiveAction(c Component) string {
	base := "Chạy script Archived để `cp` cấu hình hiện tại (unit file / config / compose / danh sách image) vào thư mục `archive-<UTC-timestamp>` ngay bên cạnh plan."
	if len(volumeWarnings(c)) > 0 {
		base += " BẮT BUỘC backup tay toàn bộ volume dữ liệu trước khi tiếp tục — tool không tự xóa và không tự backup dữ liệu."
	}
	return base
}

func archiveScript(c Component, warnings []string) string {
	head := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Archived — copy every recovery-relevant artifact BEFORE Removed.",
		"",
		`ARCHIVE="archive-$(date -u +%Y%m%dT%H%M%SZ)"`,
		`mkdir -p "$ARCHIVE"`,
		"",
	}
	var body []string
	switch c.Kind {
	case "systemd_unit", "timer":
		body = []string{
			fmt.Sprintf("systemctl cat %s > \"$ARCHIVE/%s.txt\" 2>/dev/null || true", c.Name, c.Name),
			fmt.Sprintf("systemctl show %s -p FragmentPath --value | xargs -r -I{} cp {} \"$ARCHIVE/\" 2>/dev/null || true", c.Name),
		}
	case "container":
		body = []string{
			fmt.Sprintf("docker inspect %s > \"$ARCHIVE/inspect-%s.json\"", c.Name, c.Name),
			fmt.Sprintf("docker inspect %s --format '{{.Config.Image}}' > \"$ARCHIVE/image-%s.txt\" 2>/dev/null || true", c.Name, c.Name),
		}
	case "cron_job":
		f := attrOr(c.Attrs, "file", "")
		if f != "" {
			body = []string{fmt.Sprintf("cp %q \"$ARCHIVE/\"", f)}
		} else {
			body = []string{"crontab -l > \"$ARCHIVE/crontab.bak\" 2>/dev/null || true"}
		}
	case "nginx_route":
		body = []string{
			"cp -a /etc/nginx \"$ARCHIVE/nginx/\" 2>/dev/null || cp -a /etc/nginx/sites-enabled \"$ARCHIVE/\"",
		}
	default:
		body = []string{fmt.Sprintf("# no standard archive source for kind %q", c.Kind)}
	}
	warn := []string{"", "# Data volumes are NEVER deleted automatically — confirm your backup first."}
	for _, w := range warnings {
		warn = append(warn,
			fmt.Sprintf("echo 'Volume %s có thể còn dữ liệu — xác nhận đã backup trước khi tiếp tục' >&2", w),
			fmt.Sprintf("# manual backup of %s happens here; no command is generated", w))
	}
	tail := []string{"", "echo \"Đã archive vào $ARCHIVE — xác nhận trước khi qua Removed.\""}
	return strings.Join(append(append(head, body...), append(warn, tail...)...), "\n") + "\n"
}

func removedAction(c Component) string {
	switch c.Kind {
	case "container":
		return "Gỡ theo đúng 3 mục riêng biệt: container → image → volume (mỗi lệnh một rollback riêng; volume chỉ xóa khi đã xác nhận backup)."
	case "systemd_unit", "timer":
		return "Xóa unit file + daemon-reload (chỉ sau khi đã archive)."
	case "cron_job":
		return "Xóa file cron đã disable (chỉ sau khi đã archive)."
	case "nginx_route":
		return "Xóa vĩnh viễn block route đã comment trong config (chỉ sau khi đã archive)."
	default:
		return fmt.Sprintf("Gỡ %s bằng cơ chế của loại này — xem script.", c.Kind)
	}
}

func removedScript(c Component) string {
	head := []string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Removed — delete for real. Archive MUST exist before this stage.",
	}
	var body []string
	switch c.Kind {
	case "container":
		img := attrOr(c.Attrs, "image", "")
		vols := volumeWarnings(c)
		body = []string{
			fmt.Sprintf("docker rm %s", c.Name),
			"# rollback: docker run ... (không có trực tiếp — dựng lại từ compose/inspect đã archive)",
			"",
			"# --- image (riêng biệt, KHÔNG gộp với container) ---",
		}
		if img != "" {
			body = append(body,
				fmt.Sprintf("docker rmi %s", img),
				fmt.Sprintf("# rollback: docker pull %s", img))
		} else {
			body = append(body, "# image unknown — lấy từ archive/image-*.txt rồi rmi tay")
		}
		body = append(body, "", "# --- volume (riêng biệt; chỉ khi đã backup tay) ---")
		if len(vols) == 0 {
			body = append(body, "# no named volumes attached")
		}
		for _, v := range vols {
			body = append(body,
				fmt.Sprintf("# Volume %s có thể còn dữ liệu — xác nhận đã backup trước khi bỏ comment dòng sau:", v),
				fmt.Sprintf("# docker volume rm %s", volumeName(v)),
				"# rollback: không có — khôi phục từ backup bạn đã xác nhận ở Archived")
		}
	case "systemd_unit", "timer":
		body = []string{
			fmt.Sprintf("systemctl disable --now %s 2>/dev/null || true", c.Name),
			fmt.Sprintf("rm -f /etc/systemd/system/%s /lib/systemd/system/%s 2>/dev/null || true", c.Name, c.Name),
			"systemctl daemon-reload",
			fmt.Sprintf("# rollback: copy %s.txt từ archive/ về /etc/systemd/system/ rồi daemon-reload + enable --now", c.Name),
		}
	case "cron_job":
		f := attrOr(c.Attrs, "file", "")
		if f == "" {
			body = []string{"# remove the crontab entry manually using the archived crontab.bak as reference",
				"# rollback: restore from archive/crontab.bak"}
		} else {
			body = []string{
				fmt.Sprintf("rm -f %q %q 2>/dev/null || true", f, f+".disabled"),
				fmt.Sprintf("# rollback: cp từ archive/ về %q rồi xác nhận lại", f),
			}
		}
	case "nginx_route":
		body = []string{
			"# Xóa vĩnh viễn block route trong config (sau khi đã có bản archive) rồi:",
			"nginx -t && systemctl reload nginx",
			"# rollback: restore file nginx từ archive/ rồi reload",
		}
	default:
		body = []string{fmt.Sprintf("# no standard removal command for kind %q", c.Kind)}
	}
	return strings.Join(append(head, append(body, "", "# end removal")...), "\n") + "\n"
}

func verifiedScript(ref string) string {
	return strings.Join([]string{
		"#!/usr/bin/env bash",
		"set -euo pipefail",
		"",
		"# Verified — prove the component is gone and nothing else broke.",
		"archaeologist scan --db archaeologist.db",
		fmt.Sprintf("archaeologist delete-check %q --db archaeologist.db || true", ref),
		"",
		"# rollback: none — if delete-check still resolves the component,",
		"# return to Removed and inspect the archive for a missed path.",
	}, "\n") + "\n"
}

// attrOr returns attrs[key] or fallback.
func attrOr(attrs map[string]string, key, fallback string) string {
	if v := strings.TrimSpace(attrs[key]); v != "" {
		return v
	}
	return fallback
}

// volumeName extracts the volume name from a docker mount string
// ("data:/var/lib/x" → "data"); anonymous host paths fall back to the
// full string.
func volumeName(mount string) string {
	if i := strings.IndexByte(mount, ':'); i > 0 {
		return mount[:i]
	}
	return mount
}
