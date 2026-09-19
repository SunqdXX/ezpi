module ezpitun

go 1.27.3

require (
	ezpi v0.0.0-00010101000000-000000000000
	gvisor.dev/gvisor v0.0.0-20261108065553-978c3a04e886
)

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/mobile v0.0.0-20261011034528-197770444867 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
)

tool golang.org/x/mobile/cmd/gobind

replace ezpi => ../../daemon
