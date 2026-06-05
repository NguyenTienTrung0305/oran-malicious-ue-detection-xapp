import pandas as pd
import sys

df = pd.read_csv(sys.argv[1])  # labeled.csv (LONG)

# Pivot
df_wide = df.pivot_table(
    index=["timestamp", "scenario"],
    columns="ue_id",
    values=["DRB.UEThpDl", "DRB.UEThpUl",
            "RRU.PrbUsedDl", "RRU.PrbUsedUl", "RRU.PrbAvailDl",
            "DRB.AirIfDelayUl", "DRB.RlcSduDelayDl", "DRB.RlcPacketDropRateDl"]
).reset_index()

# Flatten + rename
df_wide.columns = ['timestamp', 'scenario'] + [
    f"{metric_name_map[col[0]]}_{col[1]}" 
    for col in df_wide.columns[2:]
]

# Map labels per UE
labels = df.groupby(["scenario", "ue_id"])["is_malicious"].first().unstack()
df_wide["label_0"] = df_wide["scenario"].map(labels[0])
df_wide["label_1"] = df_wide["scenario"].map(labels[1])

df_wide.to_csv(sys.argv[2], index=False)