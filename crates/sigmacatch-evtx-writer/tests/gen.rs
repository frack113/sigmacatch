#[test]
fn generate_evtx_roundtrips() {
    const XML: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-TaskScheduler" Guid="{de7b24ea-73c8-4a09-985d-5bdadcfa9017}"/>
    <EventID>106</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>106</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-01-15T10:30:45.1234567Z"/>
    <EventRecordID>1</EventRecordID>
    <Correlation/>
    <Execution ProcessID="1234" ThreadID="5678"/>
    <Channel>Microsoft-Windows-TaskScheduler/Operational</Channel>
    <Computer>WIN-TEST</Computer>
    <Security UserID="S-1-5-18"/>
  </System>
  <EventData>
    <Data Name="TaskName">\MyTask &amp; More</Data>
    <Data Name="TaskInstanceId">abc-123</Data>
  </EventData>
</Event>"#;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("event.evtx");
    sigmacatch_evtx_writer::write_evtx_from_xml(XML, 1, &path).unwrap();

    let events = input_evtx::parse_evtx_file(&path).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_json["Event"]["System"]["EventID"], 106);
}
