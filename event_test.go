package sevStep

import (
	"bytes"
	"encoding/hex"
	"io"
	"reflect"
	"testing"
)

func Test_parseEvent(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		args    args
		want    *Event
		wantErr bool
	}{
		{
			name: "With MonitorGPA and Content field",
			args: args{
				s: `{"id":4,"faulted_gpa":985686016,"error_code":20,"have_rip_info":true,"rip":139969225768391,"monitor_gpa":959684384,"content":"0x7e6927d61379d2620800000030000000"}`,
			},
			want: &Event{
				ID:          4,
				FaultedGPA:  985686016,
				ErrorCode:   20,
				HaveRipInfo: true,
				RIP:         139969225768391,
				MonitorGPA:  959684384,
				Content: func() jsonBytes {
					s, err := hex.DecodeString("7e6927d61379d2620800000030000000")
					if err != nil {
						t.Fatalf("Failed to prepare test case: %v", err)
					}
					return s
				}(),
			},
			wantErr: false,
		},
		{
			name: "Without MonitorGPA and Without Content Field",
			args: args{
				s: `{"id":4,"faulted_gpa":985686016,"error_code":20,"have_rip_info":true,"rip":139969225768391}`,
			},
			want: &Event{
				ID:          4,
				FaultedGPA:  985686016,
				ErrorCode:   20,
				HaveRipInfo: true,
				RIP:         139969225768391,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseEventFromJSON(tt.args.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseEventFromJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseEventFromJSON() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseInFile(t *testing.T) {
	type args struct {
		r io.Reader
	}
	tests := []struct {
		name    string
		args    args
		want    []*Event
		wantErr bool
	}{
		{
			name: "Short Input",
			args: args{
				r: bytes.NewReader([]byte(`
parsing monitor gpa argopened /dev/kvm
issueing KVM_USPT_REGISTER_PID for pid 296398
issuing KVM_TRACK_PAGE call for page 1
entering poll loop
initial poll_sate was 1000
{"id":2,"faulted_gpa":985686016,"error_code":20,"have_rip_info":true,"rip":140544715189648,"monitor_gpa":1442398976,"content":"0x7ab3aa4a3a6352860800000030000000"}
issuing KVM_TRACK_PAGE to retrack 0x3badb000
done!
handled 1 events
`)),
			},
			want: []*Event{
				{
					ID:          2,
					FaultedGPA:  985686016,
					ErrorCode:   20,
					HaveRipInfo: true,
					RIP:         140544715189648,
					MonitorGPA:  1442398976,
					Content: func() jsonBytes {
						s, err := hex.DecodeString("7ab3aa4a3a6352860800000030000000")
						if err != nil {
							t.Fatalf("Failed to prepare test case: %v", err)
						}
						return s
					}(),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseInputFile(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseInputFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseInputFile() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_eventCountBetweenMarkerPage(t *testing.T) {
	type args struct {
		events            []*Event
		vaddrOfMarkerPage uint64
	}
	tests := []struct {
		name string
		args args
		want [][]int
	}{
		{
			name: "Normal",
			args: args{
				events: []*Event{
					{
						ID:          0,
						FaultedGPA:  0x1000,
						ErrorCode:   0,
						HaveRipInfo: true,
						RIP:         0x7ff1000,
					},
					{
						ID:          0,
						FaultedGPA:  0x2000,
						ErrorCode:   0,
						HaveRipInfo: true,
						RIP:         0x7ff2000,
					},
					{
						ID:          0,
						FaultedGPA:  0x3000,
						ErrorCode:   0,
						HaveRipInfo: true,
						RIP:         0x7ff3000,
					},
					{
						ID:          0,
						FaultedGPA:  0x1000,
						ErrorCode:   0,
						HaveRipInfo: true,
						RIP:         0x7ff1000,
					},
				},
				vaddrOfMarkerPage: 0x7ff1000,
			},
			want: [][]int{{1, 2}},
		},
		{
			name: "Zero Between",
			args: args{
				events: []*Event{
					{
						ID:          0,
						FaultedGPA:  0x1000,
						ErrorCode:   0,
						HaveRipInfo: true,
						RIP:         0x7ff1000,
					},
					{
						ID:          0,
						FaultedGPA:  0x1000,
						ErrorCode:   0,
						HaveRipInfo: true,
						RIP:         0x7ff1000,
					},
				},
				vaddrOfMarkerPage: 0x7ff1000,
			},
			want: [][]int{{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EventsBetweenMarkerPage(tt.args.events, tt.args.vaddrOfMarkerPage); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("eventCountBetweenMarkerPage() = %v, want %v", got, tt.want)
			}
		})
	}
}
