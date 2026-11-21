package master

import "testing"

func TestPanelXrayWithIndependentCheckpoint(t *testing.T) {
	testPanelXraySelectSignDeliverAndConfirm(t, func(t *testing.T, client taskTestClient) {
		enrollTestCheckpoint(t, client)
	})
}
