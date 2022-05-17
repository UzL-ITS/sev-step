package sevStep

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

type jsonBytes []byte

func (h jsonBytes) MarshalJSON() ([]byte, error) {
	buf := &bytes.Buffer{}
	//encode as hex string, to make raw json more human friendly
	//we need quotes around our value for json to be happy
	if _, err := buf.WriteString("\""); err != nil {
		return nil, err
	}
	encoder := hex.NewEncoder(buf)
	if _, err := encoder.Write(h); err != nil {
		return nil, err
	}
	if _, err := buf.WriteString("\""); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (h *jsonBytes) UnmarshalJSON(b []byte) error {
	//sanitize for hex parser, as json input might have literal quotes and/or 0x prefix
	s := strings.TrimPrefix(strings.Trim(string(b), `""`), "0x")
	buf, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("failed to unmarshal jsonBytes : %v", err)
	}
	*h = buf
	return nil
}

type Event struct {
	ID                      uint64    `json:"id"`
	FaultedGPA              uint64    `json:"faulted_gpa"`
	ErrorCode               uint32    `json:"error_code"`
	HaveRipInfo             bool      `json:"have_rip_info"`
	RIP                     uint64    `json:"rip"`
	MonitorGPA              uint64    `json:"monitor_gpa,omitempty"`
	Content                 jsonBytes `json:"content,omitempty"`
	Timestamp               time.Time `json:"timestamp"`
	HaveRetiredInstructions bool      `json:"have_retired_instructions"`
	//RetiredInstructions are the instructions retired in the guest
	//between this and the previous (by ID) page fault event
	RetiredInstructions uint64 `json:"retired_instructions"`
}

func (e Event) String() string {
	retInstr := "not measured"
	if e.HaveRetiredInstructions {
		retInstr = fmt.Sprintf("%v", e.RetiredInstructions)
	}
	return fmt.Sprintf("ID %d, FaultedGPA %x, HaveRip %t, RIP %x, Timestamp %v Retired Instructions %v", e.ID,
		e.FaultedGPA, e.HaveRipInfo, e.RIP, e.Timestamp.Format(time.StampNano), retInstr)
}

func (e Event) HasAccessData() bool {
	return e.MonitorGPA != 0
}

func ParseEventFromJSON(s string) (*Event, error) {
	event := &Event{}
	if err := json.Unmarshal([]byte(s), event); err != nil {
		return nil, err
	}
	return event, nil
}

func ParseInputFile(r io.Reader) ([]*Event, error) {
	sc := bufio.NewScanner(r)
	sc.Split(bufio.ScanLines)

	events := make([]*Event, 0)

	printedWarningNonJSON := false
	printedWarningNoRIP := false
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "{") {
			if !printedWarningNonJSON {
				log.Printf("omiting non json lines")
			}
			printedWarningNonJSON = true
			continue
		}

		v, err := ParseEventFromJSON(line)
		if err != nil {
			return nil, fmt.Errorf("ParseEventFromJSON failed on %s : %v", line, err)
		}

		if !v.HaveRipInfo && !printedWarningNoRIP {
			log.Printf("Some entries do not have RIP info")
			printedWarningNoRIP = true
		}

		events = append(events, v)

	}
	if sc.Err() != nil {
		return nil, fmt.Errorf("scanner error : %v", sc.Err())
	}
	return events, nil
}

//FilterEvents extracts entries fulfilling filter. No deep copy!
func FilterEvents(events []*Event, filter func(e *Event) bool) []*Event {
	res := make([]*Event, 0)

	for _, v := range events {
		if filter(v) {
			res = append(res, v)
		}
	}
	return res
}

func EventsBetweenMarkerPage(events []*Event, vaddrOfMarkerPage uint64) [][]int {
	//get indices of all events on marker page
	idxOfMarkerEvents := make([]int, 0)
	for i, v := range events {
		if OnSamePage(v.RIP, vaddrOfMarkerPage) {
			idxOfMarkerEvents = append(idxOfMarkerEvents, i)
		}
	}

	eventsBetweenMarkerEvents := make([][]int, 0)
	for idx := 0; idx < len(idxOfMarkerEvents)-1; idx++ {
		eventsBetween := idxOfMarkerEvents[idx+1] - idxOfMarkerEvents[idx] - 1
		buf := make([]int, 0, eventsBetween)
		for i := idxOfMarkerEvents[idx] + 1; i < idxOfMarkerEvents[idx+1]; i++ {
			buf = append(buf, i)
		}
		eventsBetweenMarkerEvents = append(eventsBetweenMarkerEvents, buf)

	}

	return eventsBetweenMarkerEvents
}
