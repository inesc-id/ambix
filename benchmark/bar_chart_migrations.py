import matplotlib.pyplot as plt
import argparse
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument("--ambix")
parser.add_argument("--both")

if __name__ == "__main__":
    args = parser.parse_args()
    migrations_ambix = int(args.ambix)
    migrations_both = int(args.both)

    x = np.arange(2)

    migrations = [migrations_ambix, migrations_both]
    labels = ["Ambix", "Ambix + Hmalloc"]

    p1 = plt.bar(x[0], migrations[0])
    p2 = plt.bar(x[1], migrations[1])
    # Add text labels over the bars
    for i, v in enumerate(migrations):
        plt.text(i, v + 0.5, labels[i], ha='center', va='bottom')

    for i, v in enumerate(migrations):
        plt.axhline(y=v, color='gray', linestyle='--')

        plt.text(-0.5, v, str(v), ha='right', va='center')

    plt.xticks(x, [])
    plt.ylabel("Number of Migrations")
    plt.title("Number of Migrations per System")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()
