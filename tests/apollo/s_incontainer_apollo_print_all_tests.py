import unittest
import sys

last_suite=None
last_class=None
count=0
usage_str="usage: s_incontainer_apollo_print_all_tests.py (h)ierarchy | (f)lat | (s)uites | (c)lasses | (t)ests"
tests_list = []

def print_suite(suite, mode):
    global last_suite, last_class, count, tests_list
    
    if hasattr(suite, '__iter__'):
        for x in suite:
            print_suite(x, mode)
    else:
        s1 = str(suite).replace("(", "").replace(")", "").split(" ")
        s2 = s1[1].split(".")
        s2.append(s1[0])

        full_test_repr = f"{s2[0]}.{s2[1]}.{s2[2]}"
        if f"{s2[0]}.{s2[1]}.{s2[2]}" in tests_list:
            return
        tests_list.append(full_test_repr)

        if mode == "h":
            if last_suite != s2[0]:
                print(s2[0], end =".")
                last_suite = s2[0]
            else:
                print(" " * (len(s2[0])+1), end="")
            if last_class != s2[1]:
                print(s2[1], end =".")
                last_class = s2[1]
            else:
                print(" " * (len(s2[1])+1), end="")
            print(f"{s2[2]}")
            count += 1
        elif mode == "f":
            print(full_test_repr)
            count += 1
        elif mode == "t":
            print(f"{s2[2]}")
            count += 1
        elif mode == 's':
            if last_suite != s2[0]:
                print(s2[0])
                last_suite = s2[0]
                count += 1
        elif mode == 'c':
            if last_class != s2[1]:
                print(f"{s2[0]}.{s2[1]}")
                last_class = s2[1]
                count += 1
        else:
            raise Exception(usage_str)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(usage_str)
        sys.exit(1)
    mode = sys.argv[1]
    print_suite(unittest.defaultTestLoader.discover('.'), mode)
    print("=" * 16)
    print("Total tests: " + str(count))