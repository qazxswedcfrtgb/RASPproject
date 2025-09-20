import pandas as pd
import os

# 讀取原始CSV
df = pd.read_csv("payload_full.csv")

# 確保欄位存在
if "payload" not in df.columns or "attack_type" not in df.columns:
    raise ValueError("缺少必要欄位 'payload' 或 'attack_type'")

# 建立輸出資料夾（可選）
output_dir = "split_by_attack_type"
os.makedirs(output_dir, exist_ok=True)

# 依 attack_type 分組並輸出檔案
for attack_type, group in df.groupby("attack_type"):
    output_filename = f"{attack_type}.csv"
    output_path = os.path.join(output_dir, output_filename)

    # 只保留 payload 欄位
    group[["payload"]].to_csv(output_path, index=False)

print("分檔完成。")

