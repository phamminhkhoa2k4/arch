// Package cleanup builds staged cleanup plans: six gate-checked
// stages, each with executable commands and matching rollbacks. The
// package only describes and writes files — it never runs anything.
package cleanup

// StageNames is the fixed six-stage machine, in order.
var StageNames = []string{
	"Candidate", "Quarantined", "Observed", "Archived", "Removed", "Verified",
}

// ScriptFiles maps each stage to its file name inside the plan dir.
var ScriptFiles = map[string]string{
	"Candidate":   "01-candidate.sh",
	"Quarantined": "02-quarantined.sh",
	"Observed":    "03-observed.sh",
	"Archived":    "04-archived.sh",
	"Removed":     "05-removed.sh",
	"Verified":    "06-verified.sh",
}

// Component identifies the cleanup target.
type Component struct {
	Kind        string
	Name        string
	IdentityKey string
	Ref         string // the delete-check reference (name or identity key)
	Attrs       map[string]string
}

// Stage is one plan step: what to do, how to know it worked, who
// signs off, and which script file carries the commands.
type Stage struct {
	Name      string
	Action    string
	Gate      string
	Confirmer string
	Script    string // shell body (commands + "# rollback:" comments)
}

// Plan is the full staged cleanup plan for one component.
type Plan struct {
	Component Component
	Stages    []Stage
	// VolumeWarnings lists data-bearing volumes that must be backed
	// up by hand before anything is deleted; the tool never removes
	// them itself.
	VolumeWarnings []string
}
