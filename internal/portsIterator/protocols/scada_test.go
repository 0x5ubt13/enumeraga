package protocols

import (
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// TestPROFINETHonoursTheAuthorisedUDPProtocol verifies that PROFINET runs its
// profinet-cm-lookup NSE scan over UDP and only when UDP 34964 is in scope.
func TestPROFINETHonoursTheAuthorisedUDPProtocol(t *testing.T) {
	for _, tt := range []struct {
		name  string
		ports string
		want  int
	}{
		{name: "UDP authorised launches the UDP NSE scan", ports: "U:34964", want: 1},
		{name: "both protocols authorised launches the UDP NSE scan", ports: "34964,U:34964", want: 1},
		{name: "TCP only suppresses the UDP scan", ports: "34964", want: 0},
		{name: "unbounded launches the UDP NSE scan", ports: "", want: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setBounds(t, bounds.Config{Ports: tt.ports, MaxRuntimeSeconds: 1})
			utils.ToolRegistry = utils.NewToolTracker()
			utils.BaseDir = t.TempDir() + "/"
			drainWorkerPool(t)

			PROFINET("34964")
			utils.Wg.Wait()

			if got := utils.ToolRegistry.GetTotal(); got != tt.want {
				t.Errorf("launches = %d, want %d for --ports %q", got, tt.want, tt.ports)
			}
			if got := utils.ToolRegistry.CountByStatus(utils.ToolCompleted); got != 0 {
				t.Errorf("completed count = %d, want 0: nothing should execute in this test", got)
			}
		})
	}
}
