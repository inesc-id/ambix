import argparse
import matplotlib.pyplot as plt

parser = argparse.ArgumentParser()
parser.add_argument("--ambix")
parser.add_argument("--hmalloc")
parser.add_argument("--both")

if __name__ == "__main__":
    args = parser.parse_args()
    c_lines = None
    c2_lines = None
    lines = None
    if args.ambix:
        with open(args.ambix) as f:
            c_lines = [el.strip() for el in f.readlines()]
        c_lines = list(float(el.split(" ")[-1]) for el in filter(lambda s: "Trial Time:" in s, c_lines))
    if args.hmalloc:
        with open(args.hmalloc) as f:
            c2_lines = [el.strip() for el in f.readlines()]
        c2_lines = list(float(el.split(" ")[-1]) for el in filter(lambda s: "Trial Time:" in s, c2_lines))
    if args.both:
        with open(args.both) as f:
            lines = [el.strip() for el in f.readlines()]
        lines = list(float(el.split(" ")[-1]) for el in filter(lambda s: "Trial Time:" in s, lines))
    x_axis = list(range(1, len(lines) + 1))

    print(args.ambix)
    print(args.hmalloc)
    print(args.both)
    if args.ambix:
        plt.plot(
            x_axis,
            c_lines,
            label="Ambix",
            linestyle="-",
            marker="o",
        )

    if args.hmalloc:
        plt.plot(
            x_axis,
            c2_lines,
            label="Hmalloc",
            linestyle="-",
            marker="o",
        )


    if args.both:
        plt.plot(
            x_axis,
            lines,
            label="Ambix + Hmalloc",
            linestyle="-",
            marker="o",
        )

    plt.xlabel("Iteration")
    plt.ylabel("Time")
    plt.title("Time per Iteration")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()
