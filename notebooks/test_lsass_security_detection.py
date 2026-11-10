import pandas as pd

df = pd.read_csv("datasets/processed/lsass_security_events.csv")

matches = df[
    (df["EventID"] == 4663) &
    (df["ObjectType"].str.lower() == "process") &
    (df["ObjectName"].str.lower().str.endswith("lsass.exe")) &
    (df["AccessMask"].str.lower() == "0x10")
]

print("=== CYBERION DETECTION TEST 02 ===")
print(f"Total events analyzed: {len(df)}")
print(f"Matching events: {len(matches)}")

for _, event in matches.iterrows():
    print("\n[HIGH] Suspicious LSASS Memory Access")
    print(f"Time: {event['TimeCreated']}")
    print(f"Source: {event['ProcessName']}")
    print(f"Target: {event['ObjectName']}")
    print(f"User: {event['User']}")
    print("MITRE ATT&CK: T1003")

print("\nDetection test completed.")
