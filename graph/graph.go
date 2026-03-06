package graph

type Node struct {
	ID                 string `json:"id"`
	Label              string `json:"label"`
	Status             string `json:"status"`
	PID                int    `json:"pid,omitempty"`
	RawAddress         string `json:"raw_address,omitempty"`
	Host               string `json:"host,omitempty"`
	Port               string `json:"port,omitempty"`
	Process            string `json:"process,omitempty"`
	BindScope          string `json:"bind_scope,omitempty"`
	LikelyReachability string `json:"likely_reachability,omitempty"`
	InterfaceType      string `json:"interface_type,omitempty"`
	Exposed            bool   `json:"exposed"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}
