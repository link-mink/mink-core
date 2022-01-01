/*            _       _
 *  _ __ ___ (_)_ __ | | __
 * | '_ ` _ \| | '_ \| |/ /
 * | | | | | | | | | |   <
 * |_| |_| |_|_|_| |_|_|\_\
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <mink_utils.h>
#include <sys/stat.h>
#include <boost/tokenizer.hpp>
#include <fstream>


int mink_utils::size_bits(unsigned int input) {
    return (int)ceil(log10(input + 1) / log10(2));
}


int mink_utils::size_bytes(unsigned int input) {
    return ceil((double)size_bits(input) / 8);
}

uint32_t mink_utils::hash_fnv(const void* key, int len){
    if(key == nullptr) return 0;
    const unsigned char *p = (const unsigned char*)key;
    uint32_t h = 2166136261;
    for(int i = 0; i < len; i++) h = (h * 16777619) ^ p[i];
    return h;
}

uint32_t mink_utils::hash_fnv1a(const void* key, int len){
    if(key == nullptr) return 0;
    const unsigned char *p = (const unsigned char*)key;
    uint32_t h = 2166136261;
    for(int i = 0; i < len; i++) h = (h ^ p[i]) * 16777619;
    return h;
}

uint64_t mink_utils::hash_fnv1a_64bit(const void* key, int len){
    if(key == nullptr) return 0;
    const unsigned char *p = (const unsigned char*)key;
    uint64_t h = 14695981039346656037UL;
    for(int i = 0; i < len; i++) h = (h ^ p[i]) * 1099511628211UL;
    return h;
}


uint32_t mink_utils::hash_fnv1a_str(const char* key){
    if(key == nullptr) return 0;
    const unsigned char *p = (const unsigned char*)key;
    uint32_t h = 2166136261;
    uint32_t len = strnlen(key, 4294965097UL);
    for(unsigned int i = 0; i < len; i++) h = (h ^ p[i]) * 16777619;
    return h;
}

uint64_t mink_utils::hash_fnv1a_str_64bit(const char* key){
    if(key == nullptr) return 0;
    const unsigned char *p = (const unsigned char*)key;
    uint64_t h = 14695981039346656037UL;
    uint32_t len = strnlen(key, 4294965097UL);
    for(unsigned int i = 0; i < len; i++) h = (h ^ p[i]) * 1099511628211UL;
    return h;
}

// rollback filter
int mink_utils::_ac_rollback_revision_filter(const struct dirent* a){
    if(strncmp(a->d_name, ".rollback", 9) == 0) return 1; else return 0;
}

// timestamp sort
int mink_utils::_ac_rollback_revision_sort(const struct dirent ** a, const struct dirent ** b){
    // file stats
    struct stat st1;
    struct stat st2;
    char tmp_ch[200];
    memset(&st1, 0, sizeof(struct stat));
    memset(&st2, 0, sizeof(struct stat));

    memset(tmp_ch, 0, 200);
    memcpy(tmp_ch, "./commit-log/", 13);
    memcpy(&tmp_ch[13], (*a)->d_name, strnlen((*a)->d_name, 186));
    stat(tmp_ch, &st1);

    memset(tmp_ch, 0, 200);
    memcpy(tmp_ch, "./commit-log/", 13);
    memcpy(&tmp_ch[13], (*b)->d_name, strnlen((*b)->d_name, 186));
    stat(tmp_ch, &st2);

    if(st1.st_mtim.tv_sec > st2.st_mtim.tv_sec) return -1;
    else if(st1.st_mtim.tv_sec < st2.st_mtim.tv_sec) return 1;
    else return 0;
}

void mink_utils::tokenize(const std::string* data,
                          std::string* result,
                          int result_max_size,
                          int* result_size,
                          bool keep_quotes){

    if (!(data != nullptr && result != nullptr && result_size != nullptr))
        return;

    *result_size = 0;
    try {
        boost::tokenizer<boost::escaped_list_separator<char> > tok(
            *data, boost::escaped_list_separator<char>('\\', ' ', '\"'));
        for (auto beg = tok.begin(); beg != tok.end(); ++beg) {
            // skip empty tokens
            if (*beg != "") {
                result[(*result_size)++] = *beg;
                // keep quotes or not
                if (keep_quotes) {
                    if (result[*result_size - 1].find(' ') <
                        result[*result_size - 1].size()) {
                        result[*result_size - 1].insert(0, "\"");
                        result[*result_size - 1].append("\"");
                    }
                }
                // buffer overflow check
                if (*result_size >= result_max_size) return;
            }
        }

    } catch (const std::exception& e) {
        *result_size = 0;
        // ignore
    }
}

int mink_utils::run_external(const char* script, char* result, int result_size){
    FILE* pipe = popen(script, "r");
    if (!pipe) return -1;
    char tmp_buff[128];
    std::string tmp_res;
    // read from pipe
    while(!feof(pipe)){
        if(fgets(tmp_buff, 128, pipe) != nullptr) tmp_res += tmp_buff;
    }
    pclose(pipe);

    // check buffer size
    if(result_size >= (tmp_res.size() + 1)){
        memcpy(result, tmp_res.c_str(), tmp_res.size());
        result[tmp_res.size()] = 0;
        return 0;

    }

    return 1;
}

void mink_utils::run_external_print(const char* script, bool ncurses){
    FILE* pipe = popen(script, "r");
    if (!pipe) {
        return;
    }
    char tmp_buff[128];
    // read from pipe
    while(!feof(pipe)){
        if(fgets(tmp_buff, 128, pipe) != nullptr){
            if(ncurses) printw("%s", tmp_buff); else std::cout << tmp_buff;
        }
    }
    if(ncurses) printw("\n"); else std::cout << std::endl;
    pclose(pipe);

}

int mink_utils::cli_more(int line_c, const WINDOW* data_win, const bool* interrupt){
    int w, h, y, x, usbl_lc;
    bool more = false;
    getmaxyx(stdscr, h, w);
    getyx(stdscr, y, x);

    // usable line count
    if(line_c > h - 1){
        more = true;
        usbl_lc = h - 1;
    }else usbl_lc = line_c;

    // scrolling needed
    if(y + usbl_lc + 1 > h) {
        scrl(usbl_lc + y - h + 1);
        y = h - usbl_lc - 1;
        wmove(stdscr, h - 1, x);
        // no scrolling needed
    }else{
        wmove(stdscr, y + usbl_lc, x);

    }
    // copy win data
    copywin(data_win, stdscr, 0, 0, y, 0, y + usbl_lc - 1, w - 1, false);
    // more mode
    if(more){
        int more_c = 0;
        int dmaxrow;
        int line_diff = 0;
        // loop
        while(more && !(*interrupt)){
            // position indicator
            attron(COLOR_PAIR(8));
            printw("lines %d-%d/%d", usbl_lc * more_c + 1 + line_diff,
                   usbl_lc * more_c + usbl_lc + line_diff, line_c);
            attroff(COLOR_PAIR(8));
            refresh();
            // wait for key press
            int key_p = getch();
            // check for interrupt
            /*
            if(*interrupt){
                int y, x;
                getyx(stdscr, y, x);
                move(y, 0);
                clrtoeol();
                refresh();
                return key_p;
            }*/

            if(key_p == KEY_PPAGE){
                if(more_c > 0) {
                    --more_c;
                }else line_diff = 0;

            }else if(key_p == KEY_NPAGE || key_p == ' '){
                ++more_c;

            }else if(key_p == KEY_UP){
                if(line_diff > 0) {
                    --line_diff;
                }

            }else if(key_p == KEY_DOWN){
                if(line_diff < line_c - 1) ++line_diff;
            }


            // next chunk
            //++more_c;
            // last chunk
            if((usbl_lc * more_c + usbl_lc) + line_diff >= line_c ){
                dmaxrow = (line_c - (usbl_lc * more_c + line_diff)) - 1;
                more = false;
                // full size chunk
            }else{
                dmaxrow = usbl_lc - 1;
            }
            // clear screen
            clear();
            // copy win
             copywin(data_win,
                     stdscr,
                     // source
                     usbl_lc * more_c + line_diff,
                     0,
                     // dest
                     0,
                     0,
                     dmaxrow,
                     w - 1,
                     false);

            // update cursor position
            wmove(stdscr, dmaxrow + 1, 0);
            // refresh
            refresh();
        }

    }
    return -1;
}

int mink_utils::get_file_size(const char *filename) {
    std::ifstream ifs(filename,
                      std::ios::binary | std::ios::in | std::ios::ate);
    if (ifs.is_open()) {
        int fsize = ifs.tellg();
        ifs.close();
        return fsize;
    }
    return 0;
}

int mink_utils::load_file(const char *filename, 
                          char *result,
                          int *result_size) {
    std::ifstream ifs(filename,
                      std::ios::binary | 
                      std::ios::in | 
                      std::ios::ate);
    *result_size = 0;
    if (ifs.is_open()) {
        *result_size = ifs.tellg();
        ifs.seekg(0, std::ios::beg);
        ifs.read(result, (long)(*result_size));
        ifs.close();
        return 0;
    }
    return 1;
}

mink_utils::Randomizer::Randomizer() : dis(0,255), gen(rd()){

}

void mink_utils::Randomizer::generate(uint8_t *out, size_t nr) {
    for (size_t i = 0; i < nr; i++) out[i] = dis(gen);
}
