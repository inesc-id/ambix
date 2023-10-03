import argparse
import matplotlib.pyplot as plt
import re

regex = r"(dram|nvram),\d+,\d+,\d+,\d+,\d+,\d+"

bind_regex = r"bind,\d+,\d+"
unbind_regex = r"unbind,\d+,\d+"

labels = [
    "DRAM_MODE",
    "NVRAM_MODE",
    "NVRAM_INTENSIVE_MODE",
    "SWITCH_MODE",
    "NVRAM_WRITE_MODE",
]

parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file")
parser.add_argument("-b", "--bfs")

if __name__ == "__main__":
    args = parser.parse_args()
    timestamps_dram = [[] for _ in range(5)]
    counts_dram = [[] for _ in range(5)]
    timestamps_nvram = [[] for _ in range(5)]
    counts_nvram = [[] for _ in range(5)]
    migration_count = 0
    with open(args.file) as f:
        first = None
        last = 0
        for line in f.readlines():
            _match = re.search(regex, line)
            bind_match = re.search(bind_regex, line);
            unbind_match = re.search(unbind_regex, line);
            if bind_match is not None:
                ts = int(bind_match.group().split(",")[-1])
                if first is None:
                    first = ts
            if unbind_match is not None:
                ts = int(unbind_match.group().split(",")[-1])
                last = (ts - first) / 10 ** 9
            if _match is not None:
                mem, dram_mode, nvram_mode, nvram_intensive, switch_mode, nvram_write, ts = _match.group().split(",")

                dram_mode, nvram_mode, nvram_intensive, switch_mode, nvram_write = \
                        int(dram_mode), int(nvram_mode), int(nvram_intensive), int(switch_mode), \
                        int(nvram_write)

                migrations = [dram_mode, nvram_mode, nvram_intensive, switch_mode, nvram_write]
                if mem == "dram":  # dram -> nvram
                    for m_type, el in enumerate(migrations):
                        migration_count += el
                        if el == 0: continue
                        timestamps_dram[m_type].append((int(ts) - first) / 10**9)
                        if len(counts_dram[m_type]):
                            counts_dram[m_type].append(counts_dram[m_type][-1] + migrations[m_type])
                        else:
                            counts_dram[m_type].append(migrations[m_type])
                else:  # nvram -> dram
                    for m_type, el in enumerate(migrations):
                        if el == 0: continue
                        migration_count += el
                        timestamps_nvram[m_type].append((int(ts) - first) / 10**9)
                        if len(counts_nvram[m_type]):
                            counts_nvram[m_type].append(counts_nvram[m_type][-1] + migrations[m_type])
                        else:
                            counts_nvram[m_type].append(migrations[m_type])

    print(f"#Migrations = {migration_count}")

    max_ts = 0
    for mode in range(5):
        if len(timestamps_nvram[mode]):
            max_ts = max(timestamps_nvram[mode][-1], max_ts)
        if len(timestamps_dram[mode]):
            max_ts = max(timestamps_dram[mode][-1], max_ts)


    real_last = max(last, max_ts)

    values = None

    if args.bfs:
        with open("bfs.out", "r") as f:
            values = [(int(el.strip().split('.')[0]) - first)/10**9 for el in f.readlines()]

    # Create two separate subplots for DRAM to NVRAM and NVRAM to DRAM migrations
    plt.figure(figsize=(10, 12))

    # Subplot 1: DRAM to NVRAM Migrations
    plt.subplot(2, 1, 1)
    for mode in range(5):
        plt.plot(
            timestamps_dram[mode],
            counts_dram[mode],
            label=f"{labels[mode]}",
            linestyle="-",
            marker="o",
        )
        plt.fill_between(timestamps_dram[mode], counts_dram[mode], alpha=0.5)

    plt.xlabel("Timestamp (s)")
    plt.ylabel("Total Migrations")
    plt.title("DRAM to NVRAM Migrations")
    plt.grid(True)
    if values is not None:
        for value in values:
            plt.axvline(x=value, color='black')
    plt.legend()
    plt.xlim(0, real_last)  # Set the x-axis limits

    # Subplot 2: NVRAM to DRAM Migrations
    plt.subplot(2, 1, 2)
    for mode in range(5):
        plt.plot(
            timestamps_nvram[mode],
            counts_nvram[mode],
            label=f"{labels[mode]}",
            linestyle="-",
            marker="o",
        )
        plt.fill_between(timestamps_nvram[mode], counts_nvram[mode], alpha=0.5)

    plt.xlabel("Timestamp (s)")
    plt.ylabel("Total Migrations")
    plt.title("NVRAM to DRAM Migrations")
    plt.grid(True)
    if values is not None:
        for value in values:
            plt.axvline(x=value, color='black')
    plt.legend()
    plt.xlim(0, real_last)  # Set the x-axis limits

    # Adjust layout and display the plot
    plt.tight_layout()
    plt.show()
