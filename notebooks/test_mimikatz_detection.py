import pandas as pd

df = pd.read_csv("datasets/processed/mimikatz_lsass_events.csv")

matches = df[
    (df["EventID"] == 10) &
    (df["SourceImage"].str.lower().str.endswith("mimikatz.exe")) &
    (df["TargetImage"].str.lower().str.endswith("lsass.exe")) &
    (df["GrantedAccess"].str.lower() == "0x1010")
]

print("=== CYBERION DETECTION TEST 03 ===")
print(f"Total events analyzed: {len(df)}")
print(f"Matching events: {len(matches)}")

for _, event in matches.iterrows():
    print("\n[CRITICAL] Mimikatz LSASS Access Detected")
    print(f"Time: {event['TimeCreated']}")
    print(f"Source: {event['SourceImage']}")
    print(f"Target: {event['TargetImage']}")
    print("MITRE ATT&CK: T1003.001")

print("\nDetection test completed.")
