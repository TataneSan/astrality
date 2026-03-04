package console

import "fmt"

func BuildSSHCommand(bastionHost, nodeHost string) string {
	return fmt.Sprintf("ssh -J %s root@%s", bastionHost, nodeHost)
}
