package types

import "fmt"

type PipelineError struct {
	Stage string
	Err   error
}

func (e *PipelineError) Error() string {
	return fmt.Sprintf("pipeline error at stage %s: %v", e.Stage, e.Err)
}

func NewPipelineError(stage string, err error) error {
	return &PipelineError{Stage: stage, Err: err}
}
