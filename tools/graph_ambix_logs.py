import re
import argparse
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.ticker import ScalarFormatter

your_pid = "48477"
default_file = "/var/log/syslog"
found_program = False
first_timestamp = 0


def parse_arguments():
    parser = argparse.ArgumentParser(description='Memory Usage Visualization Tool')
    parser.add_argument('--pid', type=str, default=your_pid, help='Process ID to analyze')
    parser.add_argument('--file', type=str, default=default_file, help='Log file path')
    parser.add_argument('--graphs', nargs='+', choices=['hot_cold', 'memory_usage', 'promotion_demotion', 'score_distribution'], default=['hot_cold', 'memory_usage', 'promotion_demotion', 'score_distribution'], help='Graphs to generate')
    return parser.parse_args()


def parse_histogram(histogram_str):
	"""Parse a histogram string and return a list of counts."""
	counts = [int(count) for _, count in re.findall(r"(\d+):(\d+),?", histogram_str)]
	for count in counts[17:]:
		counts[16] += count

	return counts[:16]


def parse_log_line(line, data):
	global found_program
	global first_timestamp
	global your_pid

	regex_patterns = {
		"entry": re.compile(r"\[(\d+\.\d+)\].*ambix\.PLACEMENT:"),
		"memory_usage": re.compile(r"Usage \(bytes\) dram: (\d+)  pmem: (\d+)"),
		"hot_cold_pages": re.compile(r"Pid: (\d+), Hot: (\d+), Cold: (\d+)"),
		"promo_demo_pages": re.compile(r"Promoted: (\d+), Demoted: (\d+)"),
		"threshold": re.compile(r"g_threshold: (\d+)"),
		"histogram": re.compile(r"ambix\.PLACEMENT: 0:(.*)$"),
	}

	entry_match = regex_patterns["entry"].search(line)
	if entry_match:
		timestamp = float(entry_match.group(1))
		if match := regex_patterns["hot_cold_pages"].search(line):
			if match.group(1) == your_pid :
				if not found_program:
					found_program = True
					first_timestamp = timestamp
				data["hot_cold_timestamps"].append(int(timestamp - first_timestamp))
				data["hot_pages"].append(int(match.group(2)))
				data["cold_pages"].append(int(match.group(3)))

		if not found_program:
			return True 

		if "No bound processes..." in line:
			return False

		if match := regex_patterns["memory_usage"].search(line):
			data["memory_usage_timestamps"].append(int(timestamp - first_timestamp))
			data["dram_usage"].append(int(match.group(1)))
			data["pmem_usage"].append(int(match.group(2)))
		elif match := regex_patterns["promo_demo_pages"].search(line):
			data["promo_demo_timestamps"].append(int(timestamp - first_timestamp))
			data["promoted"].append(int(match.group(1)))
			data["demoted"].append(int(match.group(2)))
		elif match := regex_patterns["histogram"].search(line):
			histogram_str = match.group(1)
			histogram_counts = parse_histogram(histogram_str)
			data["histo_timestamps"].append(int(timestamp - first_timestamp))
			data["histograms"].append(histogram_counts)
		elif match := regex_patterns["threshold"].search(line):
			data["threshold"].append(int(match.group(1)))
			data["threshold_timestamps"].append(int(timestamp - first_timestamp))

	return True


def generate_hot_cold_graph(data):
	common_length = min(len(data["dram_usage"]), len(data["hot_cold_timestamps"]))

	total_pages_dram = np.array(data["dram_usage"][:common_length]) / 1048576
	total_pages_pmem = np.array(data["pmem_usage"][:common_length]) / 1048576
	timestamps = np.array(data['hot_cold_timestamps'][:common_length])
	hot_pages = np.array(data['hot_pages'][:common_length]) / 256
	cold_pages = np.array(data['cold_pages'][:common_length]) / 256
	index_array = np.arange(common_length)

	fig, axs = plt.subplots(2, 1, figsize=(12, 8), sharex=True) 

	# DRAM Graph: Cold Pages Proportion
	axs[0].bar(index_array, cold_pages, color='blue', width=1, label='Cold Pages (DRAM)')
	axs[0].bar(index_array, total_pages_dram - cold_pages, bottom=cold_pages, color='grey', width=1, label='Other Pages (DRAM)')
	axs[0].set_ylabel('Memory Usage MB')
	axs[0].set_title('Cold Pages in DRAM Over Time')
	axs[0].legend()

	# PMEM Graph: Hot Pages Proportion
	axs[1].bar(index_array, hot_pages, color='red', width=1, label='Hot Pages (PMEM)')
	axs[1].bar(index_array, total_pages_pmem - hot_pages, bottom=hot_pages, color='grey', width=1, label='Other Pages (PMEM)')
	axs[1].set_ylabel('Memory Usage MB')
	axs[1].set_title('Hot Pages in PMEM Over Time')
	axs[1].legend()

	tick_interval = 25
	plt.xticks(index_array[::tick_interval], timestamps[::tick_interval], rotation=90)
	plt.xlabel("Time (s)")

	plt.tight_layout() 


def generate_memory_usage_graph(data):
	total_pages_dram = np.array(data["dram_usage"]) / 1048576
	total_pages_pmem = np.array(data["pmem_usage"]) / 1048576

	plt.figure(figsize=(10, 6))
	plt.plot(data["memory_usage_timestamps"], total_pages_dram, label="Dram Usage (MB)")
	plt.plot(data["memory_usage_timestamps"], total_pages_pmem, label="PMEM Usage (MB)")
	plt.title("Memory usage Over Time")
	plt.xlabel("Time (s)")
	plt.ylabel("Memory usage MB")
	plt.legend()
	plt.grid(True)
	#plt.savefig('figure.png')


def generate_promotion_demotion_graph(data):
    # Calculate the cumulative sum of promoted and demoted pages
	cumulative_promoted = np.cumsum(data["promoted"])
	cumulative_demoted = np.cumsum(data["demoted"])
	timestamps = np.array(data['promo_demo_timestamps'])
	index_array = np.arange(len(timestamps))

	fig, axs = plt.subplots(2, 1, figsize=(12, 8), sharex=True) 

	axs[0].plot(index_array, cumulative_promoted, label="Cumulative Promoted Pages")
	axs[0].set_title(f"Cumulative Page Promotion Over Time (Average {int(cumulative_promoted[-1] / timestamps[-1])} promotions/sec)")
	axs[0].set_ylabel('Page Count')
	axs[0].legend()
	axs[0].grid(True)

	axs[1].plot(index_array, cumulative_demoted, label="Cumulative Demoted Pages")
	axs[1].set_title(f"Cumulative Page Demotion Over Time (Average {int(cumulative_demoted[-1] / timestamps[-1])} demotions/sec)")
	axs[1].set_ylabel('Page Count')
	axs[1].legend()
	axs[1].grid(True)

	tick_interval = 100  
	plt.xticks(index_array[::tick_interval], timestamps[::tick_interval], rotation=90)
	plt.xlabel("Time (s)")

	plt.tight_layout() 
	#plt.savefig('figure.png')


def generate_score_distribution_graph(data):
	colors = ["black", "blue", "yellow", "orange", "red", "white"]
	cmap = LinearSegmentedColormap.from_list("custom_gradient", colors, N=16)

	# Assuming 'data' is your structured dictionary with 'histo_timestamps' and 'histograms'
	histograms = np.array(data['histograms'])
	proportions = histograms / histograms.sum(axis=1, keepdims=True)

	# Fixing the casting issue by ensuring 'bottom' is a float array
	fig, ax = plt.subplots(figsize=(14, 7))
	timestamps = np.array(data['histo_timestamps'])
	index_array = np.arange(len(timestamps))

	num_scores = proportions.shape[1] 
	bottom = np.zeros(len(timestamps), dtype=np.float64)

	for score in range(num_scores):
		color = cmap(score / num_scores)  
		bars = ax.bar(index_array, proportions[:, score], bottom=bottom, color=color, width=1)
		bottom += proportions[:, score].astype(np.float64)  # Ensure addition as float
		bars[0].set_label(f'{score}')

	ax.set_xlabel('Time (s)')
	ax.set_ylabel('Proportion of Page Scores')
	ax.set_title('Proportional Distribution of Page Scores Over Time')
	ax.legend(title="Page Scores", bbox_to_anchor=(1.05, 1), loc='upper left')

	tick_interval = 25 
	plt.xticks(index_array[::tick_interval], timestamps[::tick_interval], rotation=90)

	plt.tight_layout()



if __name__ == "__main__":
	args = parse_arguments()
	your_pid = args.pid

	data = {
		"hot_cold_timestamps": [],
		"hot_pages": [],
		"cold_pages": [],
		"memory_usage_timestamps": [],
		"dram_usage": [],
		"pmem_usage": [],
		"promo_demo_timestamps": [],
		"promoted": [],
		"demoted": [],
		"histo_timestamps": [],
		"histograms": [],
		"threshold": [],
		"threshold_timestamps": [],
	}	

	# Parse the log file
	with open(args.file, "r") as logfile:
		for line in logfile:
			if not parse_log_line(line, data):
				break  # Stop processing if "No bound processes..." is found
    
    # Generate selected graphs
	if 'hot_cold' in args.graphs:
		generate_hot_cold_graph(data)
	if 'memory_usage' in args.graphs:
		generate_memory_usage_graph(data)
	if 'promotion_demotion' in args.graphs:
		generate_promotion_demotion_graph(data)
	if 'score_distribution' in args.graphs:
		generate_score_distribution_graph(data)


	plt.show()






