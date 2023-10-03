import matplotlib.pyplot as plt
import numpy as np
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("--generate_time_ambix")
parser.add_argument("--build_time_ambix")
parser.add_argument("--generate_time_both")
parser.add_argument("--build_time_both")
parser.add_argument("--generate_time_hmalloc")
parser.add_argument("--build_time_hmalloc")


if __name__ == "__main__":
    args = parser.parse_args()
    generate_time_ambix = int(args.generate_time_ambix)
    build_time_ambix = int(args.build_time_ambix)

    generate_time_both = int(args.generate_time_both)
    build_time_both = int(args.build_time_both)

    generate_time_hmalloc = int(args.generate_time_hmalloc)
    build_time_hmalloc = int(args.build_time_hmalloc)
    
    x = np.arange(3)

    generates = [generate_time_both, generate_time_ambix, generate_time_hmalloc]
    builds = [build_time_both, build_time_ambix, build_time_hmalloc]

    p1 = plt.bar(x, generates)
    p2 = plt.bar(x, builds, bottom = generates)
    plt.xticks(x, [])
    plt.xlabel("Both | Ambix | Hmalloc")
    plt.ylabel("Time")
    plt.title("Generate & Built Time")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()
