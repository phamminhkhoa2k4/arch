// Shared page behaviors: detail tabs, evidence raw-ref copy, the
// delete-decision modal, plan viewer, and the SVG graph renderer.
"use strict";

async function getJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error((await r.json()).error || r.statusText);
  return r.json();
}

function el(tag, attrs, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") n.className = v;
    else n.setAttribute(k, v);
  }
  for (const c of children) n.append(c);
  return n;
}

function table(headers, rows) {
  const t = el("table");
  const thead = el("thead");
  const tr = el("tr");
  for (const h of headers) tr.append(el("th", {}, h));
  thead.append(tr);
  const tbody = el("tbody");
  for (const row of rows) {
    const r = el("tr");
    for (const c of row) r.append(el("td", {}, c));
    tbody.append(r);
  }
  t.append(thead, tbody);
  return t;
}

function rawRefCell(rawRef) {
  const td = el("td");
  if (!rawRef) return td;
  const code = el("code", { class: "raw-ref", title: "Click to copy" }, rawRef);
  code.addEventListener("click", () => navigator.clipboard && navigator.clipboard.writeText(rawRef));
  td.append(code);
  return td;
}

// ---- detail tabs ----
const tabHost = document.getElementById("tab-content");
if (tabHost) {
  const entityID = tabHost.dataset.entity;
  const renderers = {
    overview: (d) => {
      const box = el("div");
      box.append(el("p", {}, `Verdict: ${d.verdict.state} · coverage ${d.verdict.coverage}`));
      const attrs = Object.entries(d.attributes || {});
      box.append(table(["Attribute", "Value"], attrs.map(([k, v]) => [k, v])));
      return box;
    },
    dependencies: (d) => table(
      ["Group", "Kind", "Neighbor", "Strength"],
      (d.neighbors || []).map((n) => [n.Group, n.EdgeKind, n.NeighborName, n.Strength])
    ),
    activity: (d) => table(
      ["Channel", "Polarity", "Strength", "Observed", "raw_ref"],
      (d.evidence || []).map((e) => {
        const tr = el("tr");
        tr.append(el("td", {}, e.Channel), el("td", {}, e.Polarity), el("td", {}, e.Strength), el("td", {}, e.ObservedAt));
        tr.append(rawRefCell(e.RawRef));
        return tr;
      })
    ),
    evidence: (d) => table(
      ["Channel", "Polarity", "Strength", "Observed", "raw_ref"],
      (d.evidence || []).map((e) => {
        const tr = el("tr");
        tr.append(el("td", {}, e.Channel), el("td", {}, e.Polarity), el("td", {}, e.Strength), el("td", {}, e.ObservedAt));
        tr.append(rawRefCell(e.RawRef));
        return tr;
      })
    ),
    history: (d) => table(
      ["Scan", "Observed", "Channel", "Polarity", "raw_ref"],
      (d.history || []).map((h) => {
        const tr = el("tr");
        tr.append(el("td", {}, String(h.ScanID)), el("td", {}, h.ObservedAt), el("td", {}, h.Channel), el("td", {}, h.Polarity));
        tr.append(rawRefCell(h.RawRef));
        return tr;
      })
    ),
    blindspots: (d) => (d.blind_spots || []).length
      ? table(["Channel", "Reason"], d.blind_spots.map((b) => [b.Channel, b.Reason]))
      : el("p", {}, "No blind spots."),
  };
  async function loadTab(name) {
    tabHost.textContent = "Loading…";
    try {
      const data = await getJSON(`/api/components/${entityID}/${name}`);
      tabHost.replaceChildren(renderers[name](data));
    } catch (e) {
      tabHost.textContent = "Error: " + e.message;
    }
  }
  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      loadTab(btn.dataset.tab);
    });
  });
  loadTab("overview");
}

// ---- delete-decision modal ----
const modal = document.getElementById("delete-modal");
if (modal) {
  const entityID = modal.dataset.entity;
  const body = document.getElementById("modal-body");
  const genBtn = document.getElementById("modal-generate");
  document.getElementById("delete-check-btn").addEventListener("click", async () => {
    modal.classList.remove("hidden");
    body.textContent = "Loading verdict…";
    genBtn.classList.add("hidden");
    try {
      const v = await getJSON(`/api/components/${entityID}/verdict`);
      body.replaceChildren();
      if (v.has_blockers) {
        body.append(el("p", { class: "verdict-bad" }, "⛔ NOT safe to delete"));
        const list = el("ul");
        for (const b of v.blockers) list.append(el("li", {}, `${b.code} ${b.text}`));
        body.append(list);
        genBtn.classList.add("hidden");
        body.append(el("p", {}, "Remove all blockers before generating a plan."));
      } else {
        body.append(el("p", { class: v.plan_eligible ? "verdict-ok" : "" },
          `Verdict: ${v.state} · coverage ${v.coverage}`));
        if (v.plan_eligible) {
          genBtn.classList.remove("hidden");
        } else {
          body.append(el("p", {}, "Verdict not eligible — only LIKELY_ORPHANED or ORPHANED."));
        }
      }
    } catch (e) {
      body.textContent = "Error: " + e.message;
    }
  });
  document.getElementById("modal-close").addEventListener("click", () => modal.classList.add("hidden"));
  genBtn.addEventListener("click", async () => {
    genBtn.disabled = true;
    try {
      const r = await fetch(`/api/components/${entityID}/plan`, { method: "POST" });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || r.statusText);
      window.location.href = data.href;
    } catch (e) {
      body.append(el("p", { class: "verdict-bad" }, "Error: " + e.message));
    } finally {
      genBtn.disabled = false;
    }
  });
}

// ---- plan viewer ----
const planHost = document.getElementById("plan-stages");
if (planHost) {
  const planID = planHost.dataset.plan;
  async function loadPlan() {
    planHost.textContent = "Loading…";
    try {
      const data = await getJSON(`/api/plans/${planID}`);
      planHost.replaceChildren();
      for (const st of data.stages) {
        const row = el("div", { class: "stage" + (st.Status === "done" ? " done" : "") });
        row.append(el("span", { class: "name" }, (st.Status === "done" ? "✓ " : "○ ") + st.Stage));
        row.append(el("span", { class: "muted" }, st.ConfirmedAt || "pending"));
        if (st.Status !== "done") {
          const btn = el("button", {}, "Mark as done");
          btn.addEventListener("click", async () => {
            btn.disabled = true;
            try {
              const r = await fetch(`/api/plans/${planID}/stages/${encodeURIComponent(st.Stage)}`, { method: "POST" });
              if (!r.ok) throw new Error((await r.json()).error || r.statusText);
              await loadPlan();
            } catch (e) {
              alert("Error: " + e.message);
              btn.disabled = false;
            }
          });
          row.append(btn);
        }
        planHost.append(row);
      }
    } catch (e) {
      planHost.textContent = "Error: " + e.message;
    }
  }
  loadPlan();
}

// ---- graph ----
const svg = document.getElementById("graph-svg");
if (svg) {
  const NS = "http://www.w3.org/2000/svg";
  const panel = document.getElementById("edge-panel");
  const detail = document.getElementById("edge-detail");
  const banner = document.getElementById("graph-banner");
  getJSON("/api/graph").then((g) => {
    if (g.truncated) {
      banner.textContent = `Graph has many nodes — showing ${g.nodes.length}/${g.total}. Use Components to filter.`;
      banner.classList.remove("hidden");
    }
    const byID = {};
    g.nodes.forEach((n, i) => {
      byID[n.id] = { ...n, x: 80 + (i % 5) * 190, y: 60 + Math.floor(i / 5) * 90 };
    });
    for (const e of g.edges) {
      const a = byID[e.src], b = byID[e.dst];
      if (!a || !b) continue;
      const line = document.createElementNS(NS, "line");
      line.setAttribute("x1", a.x); line.setAttribute("y1", a.y);
      line.setAttribute("x2", b.x); line.setAttribute("y2", b.y);
      line.setAttribute("stroke", e.strength === "deterministic" ? "#2563eb" : "#9ca3af");
      line.setAttribute("stroke-width", "2");
      line.style.cursor = "pointer";
      line.addEventListener("click", () => {
        detail.replaceChildren(
          el("p", {}, `${a.name} → ${b.name}`),
          el("p", {}, `kind: ${e.kind}`),
          el("p", {}, `strength: ${e.strength}`),
          el("p", {}, `channel: ${e.channel}`),
        );
        detail.append(rawRefCell(e.raw_ref));
        panel.classList.remove("hidden");
      });
      svg.append(line);
    }
    for (const n of Object.values(byID)) {
      const c = document.createElementNS(NS, "circle");
      c.setAttribute("cx", n.x); c.setAttribute("cy", n.y); c.setAttribute("r", 10);
      c.setAttribute("fill", "#2563eb");
      svg.append(c);
      const t = document.createElementNS(NS, "text");
      t.setAttribute("x", n.x + 14); t.setAttribute("y", n.y + 4);
      t.setAttribute("font-size", "11");
      t.textContent = n.name.length > 24 ? n.name.slice(0, 22) + "…" : n.name;
      svg.append(t);
    }
  }).catch((e) => {
    banner.textContent = "Error loading graph: " + e.message;
    banner.classList.remove("hidden");
  });
}
