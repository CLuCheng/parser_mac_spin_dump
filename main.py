import os
import sys
import time
from subprocess import Popen, PIPE

arch = 'x86_64'


def process_bar(num, total):
    rate = float(num) / total
    rate = round(rate * 100, 2)
    rate_num = int(rate)
    r = '\r[{}{}]{:.2f}%'.format('*' * int(rate_num / 2), ' ' * int(50 - int(rate_num / 2)), rate)
    sys.stdout.write(r)
    sys.stdout.flush()


def split_file(file_name):
    f = open(file_name)
    lines = []
    line = f.readline()
    while line:
        lines.append(line)
        line = f.readline()
    f.close()
    return lines


def find_module_addr_by_load_address(line):
    absolute_addr_begin = line.find("load address")
    absolute_addr_end = line[absolute_addr_begin:].find("+")

    if absolute_addr_begin != -1 and absolute_addr_end != -1:
        absolute_addr_end = absolute_addr_begin + absolute_addr_end - 1
        absolute_addr_begin += len("load address") + 1
        s = line[absolute_addr_begin: absolute_addr_end]
        return int(s, 16)
    return -1


def find_first_module_addr(lines, module):
    # 1001  ??? (libxxx.dylib + 5565485)[0x10cd90c2d]
    module_addr = -1
    for line in lines:
        line_str = str(line)
        if line_str.find(module) != -1 and line_str.find('???') != -1:
            module_addr = find_module_addr_by_load_address(line_str)
            if module_addr != -1:
                return module_addr
            absolute_addr_begin = line_str.rfind('[')
            absolute_addr_end = line_str.rfind(']')
            if absolute_addr_begin != -1 and absolute_addr_end != -1:
                absolute_addr = int(line_str[absolute_addr_begin + 1: absolute_addr_end], 16)
                left = line_str[0:absolute_addr_begin]
                relative_addr_begin = left.rfind('+ ')
                relative_addr_end = left.rfind(')')
                relative_addr = int(left[relative_addr_begin + 2:relative_addr_end], 10)
                module_addr = absolute_addr - relative_addr
                break
    return module_addr


def analysis_replace_lines(lines, path, module, map_module_addr):
    results = []
    i = 0
    cnt = len(lines)
    process = Popen(["atos", "-a", arch, "-o", path, '-l', str(hex(map_module_addr[module]))], stdout=PIPE, stdin=PIPE,
                    stderr=PIPE,
                    text=True)
    need_process_id = []
    need_process_addr = []
    for line in lines:
        line_str = str(line)
        if line_str.find(module) != -1 and line_str.find('???') != -1:
            absolute_addr_begin = line_str.rfind('[')
            absolute_addr_end = line_str.rfind(']')
            if absolute_addr_begin != -1 and absolute_addr_end != -1:
                absolute_addr = int(line_str[absolute_addr_begin + 1: absolute_addr_end], 16)
                need_process_id.append(i)
                need_process_addr.append(str(hex(absolute_addr)))
                results.append(line_str)
        else:
            results.append(line)
        i += 1
        process_bar(i - len(need_process_id), cnt)
    out, err = process.communicate(input='\n'.join(need_process_addr))
    out = out.split('\n')
    idx = 0
    while idx < len(need_process_id) and idx < len(out):
        if (need_process_id[idx] > len(results)-1):
            print('out of range')
            break
        results[need_process_id[idx]] = results[need_process_id[idx]].replace('???', out[idx])
        idx += 1
        process_bar(cnt - len(need_process_id) + idx, cnt)

    return results


def save_file(file_name, lines):
    f = open(file_name, 'w')
    for line in lines:
        f.write(line)
    f.close()


def find_arch_token(lines):
    global arch
    for line in lines:
        if line.find("Architecture:") != -1:
            if line.find("x86_64") != -1:
                arch = "x86_64"
            else:
                arch = "arm64"
            break


def parser_dsym(dump_file, dsym_file):
    start_time = time.time()
    lines = split_file(dump_file)
    results = []
    begin = dsym_file.rfind('/')
    end = dsym_file.rfind('.dylib')
    need_process = False
    if end == -1:
        end = dsym_file.rfind('.dSYM')
    module_name = dsym_file[begin + 1:end]
    cur_idx = 0
    find_arch_token(lines)
    while cur_idx < len(lines):
        process_name = ''
        process_lines = []
        while cur_idx < len(lines):
            line = lines[cur_idx]
            left = line.find('Process:   ')
            if left != 0:
                process_lines.append(line)
                cur_idx += 1
                continue
            process_name = line[len('Process:   '):].strip()
            process_lines.append(line)
            cur_idx += 1
            break

        while cur_idx < len(lines):
            line = lines[cur_idx]
            left = line.find('Process:   ')
            if left != 0:
                cur_idx += 1
                process_lines.append(line)
                continue
            break

        map_module_addr = {}
        if begin != -1 and end != -1:
            module_addr = find_first_module_addr(process_lines, module_name)
            if map_module_addr != -1:
                map_module_addr[module_name] = module_addr
            if module_addr == -1:
                results += process_lines
                continue
        print("process ", process_name, module_name, "module addr is ",
              hex(map_module_addr[module_name]))
        need_process = True
        results += analysis_replace_lines(process_lines, dsym_file, module_name, map_module_addr)
    print()
    save_file(dump_file, results)
    end_time = time.time()
    if need_process:
        print("{} done: {:.2f}s".format(module_name, end_time - start_time))


def read_all_dsym(cur_path):
    if cur_path[-1:] == '.' and len(cur_path) > 1:
        cur_path = cur_path[0:-1]
    if cur_path[-1:] != '/' and len(cur_path) > 1:
        cur_path += '/'
    files = os.listdir(cur_path)
    result = []
    for file in files:
        full_path = cur_path + file
        if file.endswith('.dSYM'):
            result.append(full_path)
        elif os.path.isdir(full_path):
            result += read_all_dsym(full_path)
    return result


def main():
    if len(sys.argv) < 3:
        return
    files = []
    if sys.argv[2].endswith('.') or os.path.isdir(sys.argv[2]):
        files = read_all_dsym(sys.argv[2])
    else:
        files.append(sys.argv[2])

    for file in files:
        parser_dsym(sys.argv[1], file)

    print('all done')


if __name__ == '__main__':
    main()

