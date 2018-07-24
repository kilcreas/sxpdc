/*------------------------------------------------------------------
 * Configuration validation implementation - linux code
 *
 * February 2015, Jan Omasta
 *
 * Copyright (c) 2014-2015 by cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------*/

#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/queue.h>

#include "util.h"
#include "mem.h"
#include "sxp.h"

#include "config_validate.h"

#define READ_BUF_SIZE 2048
#define CHAR_TYPES_NUM 256

#define ASSIGN_CHAR_TYPE(char_types, character, char_type) \
    char_types[*((uint8_t *)&tmp)] = char_type

TAILQ_HEAD(tailq_state_head, state);

/**
 * validation parse state enum, state parsing callback, state enum description,
 * next expected data
 * description
 */
#define TUPLE_STATE_DEF(SELECT_FUNC)                                           \
    SELECT_FUNC(STATE_NONE = 0, state_none_cb, "no data",                      \
                "Expected is setting name or comment.")                        \
    SELECT_FUNC(STATE_SETTING, state_setting_cb, "setting name",               \
                "Expected is assign character ('=' or ':') followed by "       \
                "setting value terminated by semicolon character ';'.")        \
    SELECT_FUNC(STATE_ASSIGN, state_assign_cb, "assign character('=', ':')",   \
                "Expected is setting value string(\"string\"), "               \
                "integer(1234), hexadecimal integer(0x01F), "                  \
                "boolean(FALSE, TRUE), group({}) or list'()' terminated by "   \
                "semicolon character ';'.")                                    \
    SELECT_FUNC(STATE_VALUE_0XH_0, state_value_0xh_0_cb, "integer value",      \
                "Expected is valid integer terminated by semicolon character"  \
                "';'")                                                         \
    SELECT_FUNC(STATE_VALUE_NUMBER, state_value_number_cb, "integer value",    \
                "Expected is valid integer or semicolon character ';'")        \
    SELECT_FUNC(                                                               \
        STATE_VALUE_LNUMBER, state_value_lnumber_cb, "long integer value",     \
        "Expected is valid long integer ended by semicolon character ';'")     \
    SELECT_FUNC(STATE_VALUE_0XH_L, state_value_0xh_l_cb,                       \
                "long hexadecimal value",                                      \
                "Expected is valid long hexadecimal integer value terminated " \
                "by semicolon character ';'")                                  \
    SELECT_FUNC(STATE_VALUE_0XH_X, state_value_0xh_x_cb, "hexadecimal value",  \
                "Expected is valid hexadecimal integer value terminated by "   \
                "semicolon character ';'")                                     \
    SELECT_FUNC(STATE_VALUE_0XH_H, state_value_0xh_h_cb, "hexadecimal value",  \
                "Expected is valid hexadecimal integer value terminated by "   \
                "semicolon character ';'")                                     \
    SELECT_FUNC(STATE_VALUE_STR_START, state_value_str_start_cb,               \
                "string value", "Expected is string setting value terminated " \
                                "by semicolon character ';'")                  \
    SELECT_FUNC(STATE_VALUE_STR_CNTNT, state_value_str_cntnt_cb,               \
                "string value", "Expected is string setting value terminated " \
                                "by semicolon character ';'")                  \
    SELECT_FUNC(STATE_VALUE_BOOL_TRUE, state_value_bool_true_cb,               \
                "boolean value", "Expected is valid boolean value TRUE "       \
                                 "terminated by semicolon character ';'")      \
    SELECT_FUNC(STATE_VALUE_BOOL_FALSE, state_value_bool_false_cb,             \
                "boolean value", "Expected is valid boolean value FALSE "      \
                                 "terminated by semicolon character ';'")      \
    SELECT_FUNC(STATE_GROUP_START, state_group_start_cb, "group content",      \
                "Expected is setting content or end of group character '}'")   \
    SELECT_FUNC(STATE_LIST_START, state_list_start_cb, "list content",         \
                "Expected is list content or end of list character ')' "       \
                "terminated by semicolon character ';'")                       \
    SELECT_FUNC(STATE_COMMENT, state_comment_cb, "comment",                    \
                "Expected is comment terminated by newline character.")

#define TUPLE_STATE_DEF_ENUM(enumerator, cb, string, expected) enumerator,
#define TUPLE_STATE_DEF_STR(enumerator, cb, string, expected) string,
#define TUPLE_STATE_DEF_EXP(enumerator, cb, string, expected) expected,
#define TUPLE_STATE_DEF_CB_ARRAY(enumerator, cb, string, expected) cb,
#define TUPLE_STATE_DEF_CB_DECL(enumerator, cb, string, expected)      \
    static int cb(struct validate *validate, struct state *last_state, \
                  char ch, enum char_type_e char_type);

/**
 * character types, character description
 */
#define TUPLE_CHAR_DEF(SELECT_FUNC)                              \
    SELECT_FUNC(CHAR_OTHER = 0, "other character")               \
    SELECT_FUNC(CHAR_NORMAL, "normal character")                 \
    SELECT_FUNC(CHAR_LETTER, "letter character")                 \
    SELECT_FUNC(CHAR_NUM, "digit character")                     \
    SELECT_FUNC(CHAR_SPECIAL, "special character")               \
    SELECT_FUNC(CHAR_ESCAPE, "escape character")                 \
    SELECT_FUNC(CHAR_INVISIBLE, "invisible character")           \
    SELECT_FUNC(CHAR_ASSIGN, "assign character")                 \
    SELECT_FUNC(CHAR_SEMICOLON, "semicolon character")           \
    SELECT_FUNC(CHAR_GROUP_START, "group start character")       \
    SELECT_FUNC(CHAR_GROUP_END, "group end character")           \
    SELECT_FUNC(CHAR_LIST_START, "list start character")         \
    SELECT_FUNC(CHAR_LIST_END, "list end character")             \
    SELECT_FUNC(CHAR_LIST_ITEM_DELIMITER, "list item delimiter") \
    SELECT_FUNC(CHAR_DOUBLE_QUOTES, "double quote character")    \
    SELECT_FUNC(CHAR_COMMENT_START, "comment start character")

#define TUPLE_CHAR_DEF_ENUM(enumerator, str) enumerator,
#define TUPLE_CHAR_DEF_STR(enumerator, str) str,

#define VALIDATE_ERROR(fmt, ...)                                           \
    LOG_ERROR("Syntax error on file <%s> line <%zu> position <%zu>: " fmt, \
              validate->file_path, validate->line_num, validate->line_pos, \
              ##__VA_ARGS__);                                              \
    snprintf(validate->error, validate->error_size,                        \
             "Syntax error on file <%s> line <%zu> position <%zu>: " fmt,  \
             validate->file_path, validate->line_num, validate->line_pos,  \
             ##__VA_ARGS__);                                               \
    validate->syntax_error = true;                                         \
    rc = -1;

static const char *true_str = "true";
static const char *false_str = "false";

#define CHAR_IS_LOWERCASE(ch) ((ch) >= 'a' && (ch) <= 'z')
#define CHAR_IS_UPPERCASE(ch) ((ch) >= 'A' && (ch) <= 'Z')
#define CHAR_TO_LOWERCASE(ch) \
    (CHAR_IS_LOWERCASE(ch) ? ch : (CHAR_IS_UPPERCASE(ch) ? ch + ' ' : ch))

#define CHAR_CASE_CMP(ch1, ch2) \
    (CHAR_TO_LOWERCASE(ch1) == CHAR_TO_LOWERCASE(ch2))

#define CHAR_IS_HEXA(char_type, ch)    \
    (CHAR_NUM == char_type) ||         \
        ((CHAR_LETTER == char_type) && \
         ((('a' <= ch) && ('f' >= ch)) || (('A' <= ch) && ('F' >= ch))))

/**
 * @brief validation status type
 */
enum state_e {
    TUPLE_STATE_DEF(TUPLE_STATE_DEF_ENUM) STATE_LAST,
};

/**
 * @brief character types
 */
enum char_type_e {
    TUPLE_CHAR_DEF(TUPLE_CHAR_DEF_ENUM) CHAR_TYPE_LAST,
};
/**
 * @brief validation status strings
 */
static const char *state_str[] = { TUPLE_STATE_DEF(TUPLE_STATE_DEF_STR) };

/**
 * @brief description what next is expected
 */
static const char *state_expected[] = { TUPLE_STATE_DEF(TUPLE_STATE_DEF_EXP) };

/**
 * @brief character type strings
 */
static const char *char_str[] = { TUPLE_CHAR_DEF(TUPLE_CHAR_DEF_STR) };

/**
 * @brief get validation status string by validation status type
 *
 * @param type state enum
 * @return state string or NULL
 */
static const char *state_to_str(enum state_e type)
{
    const char *ret = NULL;

    if (type < STATE_LAST) {
        ret = state_str[type];
    }

    return ret;
}

static const char *state_to_expected(enum state_e type)
{
    const char *ret = NULL;

    if (type < STATE_LAST) {
        ret = state_expected[type];
    }

    return ret;
}

static enum char_type_e char_to_type(enum char_type_e *char_types,
                                     uint8_t *character)
{
    assert((NULL != char_types) && (NULL != character));
    return char_types[*character];
}

static const char *char_type_to_str(enum char_type_e type)
{
    const char *ret = NULL;

    if (type < CHAR_TYPE_LAST) {
        ret = char_str[type];
    }

    return ret;
}

/**
 * @brief validation status informations
 */
struct state {
    TAILQ_ENTRY(state) tailq_entries;
    enum state_e flag;
    bool finished;
    size_t char_num;
    size_t line_num;
    size_t line_pos;
    bool escaped;
};

static void state_free(struct state *state)
{
    int rc = 0;
    PARAM_NULL_CHECK(rc, state);

    if (RC_ISOK(rc)) {
        mem_free(state);
    }
}

/**
 * @brief validation
 */
struct validate {
    struct tailq_state_head tailq_head; /* List head. */
    const char *file_path;              /* file path */
    FILE *file;                         /* file descriptor */
    char read_buf[READ_BUF_SIZE]; /* read buffer to do not read character by
                                     character */
    size_t read_buf_len;          /* buffer read data length */
    size_t read_buf_pos;          /* buffer read position */
    size_t line_num;              /* current line */
    size_t line_pos;              /* read position on current line */
    bool newline_n;               /* previous character was UNIX newline */
    bool newline_r;               /* previous character was OSX newline */
    bool newline;                 /* newline detected */
    bool prev_setting_complete;   /* previous setting was complete */
    bool list_is_emty;            /* actual list is empty */
    bool syntax_error; /* syntax error message buffer is filled by syntax error
                          message */
    char *error;       /* syntax error message buffer */
    size_t error_size; /* syntax error message buffer size */
};

/**
 * @brief declarations of all callbacks used to parse specific actual state of
 * parser
 */
TUPLE_STATE_DEF(TUPLE_STATE_DEF_CB_DECL)

typedef int (*state_cb_t)(struct validate *validate, struct state *last_state,
                          char ch, enum char_type_e char_type);
/**
 * Array of pointers to callbacks used to parse specific actual state of parser
 * mapped by states
 */
static state_cb_t state_cb[] = { TUPLE_STATE_DEF(TUPLE_STATE_DEF_CB_ARRAY) };

static int validate_init(struct validate *validate, const char *file_path,
                         char *error, size_t error_size)
{
    int rc = 0;

    assert(NULL != validate);
    TAILQ_INIT(&validate->tailq_head);
    validate->file = NULL;

    PARAM_NULL_CHECK(rc, file_path, error);

    if (RC_ISOK(rc)) {
        validate->file_path = file_path;
        validate->file = fopen(validate->file_path, "r");
        if (NULL == validate->file) {
            rc = -1;
            LOG_ERROR("Failed to open configuration file <%s> for read",
                      validate->file_path);
        }
    }

    if (RC_ISOK(rc)) {
        memset(validate->read_buf, 0, READ_BUF_SIZE);
        validate->read_buf_len = 0;
        validate->read_buf_pos = 0;
        validate->line_num = 1;
        validate->line_pos = 0;
        validate->newline_n = false;
        validate->newline_r = false;
        validate->newline = false;
        validate->prev_setting_complete = false;
        validate->list_is_emty = true;
        validate->syntax_error = false;
        validate->error = error;
        validate->error[0] = '\0';
        validate->error_size = error_size;
    }

    return rc;
}

static void validate_deinit(struct validate *validate)
{
    struct state *state = NULL;

    assert(NULL != validate);

    validate->error = NULL;
    if (NULL != validate->file) {
        fclose(validate->file);
        validate->file = NULL;
    }

    while ((state = TAILQ_FIRST(&validate->tailq_head)) != NULL) {
        TAILQ_REMOVE(&validate->tailq_head, state, tailq_entries);
        state_free(state);
        state = NULL;
    }
}

/**
 *  reading file character by character, but caching in block of size
 *  READ_BUF_SIZE.
 *
 * @param validate validation structure
 * @param ch character
 * @return 0 on EOF, 1 on character, -1 on error
 */
static int validate_get_char(struct validate *validate, char *ch)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, validate, ch, validate->file_path, validate->file);

    if (RC_ISOK(rc)) {

        /* reading and buffering characters */
        if ((0 == validate->read_buf_len) ||
            (validate->read_buf_len <= validate->read_buf_pos)) {
            validate->read_buf_len =
                fread(validate->read_buf, 1, READ_BUF_SIZE, validate->file);
            if ((0 == validate->read_buf_len) && (0 == feof(validate->file))) {
                LOG_ERROR("File read failed");
                rc = -1;
            } else if (0 == validate->read_buf_len) {
                LOG_TRACE("File read EOF");
                rc = 0;
            } else {
                validate->read_buf_pos = 1;
                *ch = validate->read_buf[0];
                rc = 1;
            }
        } else {
            *ch = validate->read_buf[validate->read_buf_pos];
            validate->read_buf_pos++;
            rc = 1;
        }

        /* newline processing */
        if (1 == rc) {
            if ('\n' == (*ch)) {
                if (true == validate->newline_n) {
                    validate->newline = true;
                } else if (true == validate->newline_r) {
                    validate->newline = true;
                    validate->newline_r = false;
                    validate->newline_n = false;
                } else {
                    validate->newline_n = true;
                }
            } else if ('\r' == (*ch)) {
                if (true == validate->newline_r) {
                    validate->newline = true;
                } else if (true == validate->newline_n) {
                    validate->newline = true;
                    validate->newline_n = false;
                    validate->newline_r = true;
                } else {
                    validate->newline_r = true;
                }
            } else {
                if (true == validate->newline_n) {
                    validate->newline_n = false;
                    validate->newline = true;
                } else if (true == validate->newline_r) {
                    validate->newline_r = false;
                    validate->newline = true;
                }
            }

            if (true == validate->newline) {
                validate->newline = false;
                validate->line_num++;
                validate->line_pos = 0;
            } else {
                validate->line_pos++;
            }
        }
    }

    return rc;
}

static int state_insert(struct validate *validate, enum state_e flag)
{
    int rc = 0;
    struct state *state = NULL;

    PARAM_NULL_CHECK(rc, validate);

    if (RC_ISOK(rc)) {
        state = mem_calloc(1, sizeof(*state));
        if (NULL == state) {
            LOG_ERROR("out of memory to insert new state to queue: %d", rc);
            rc = ENOMEM;
        }
    }

    if (RC_ISOK(rc)) {
        state->finished = false;
        state->flag = flag;
        state->char_num = 1;
        state->line_num = validate->line_num;
        state->line_pos = validate->line_pos;
        state->escaped = false;
        TAILQ_INSERT_TAIL(&validate->tailq_head, state, tailq_entries);
    }

    return rc;
}

static int state_none_cb(struct validate *validate,
                         __attribute__((unused)) struct state *last_state,
                         char ch, enum char_type_e char_type)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, validate);

    if (RC_ISOK(rc)) {
        if (CHAR_LETTER == char_type) {
            rc = state_insert(validate, STATE_SETTING);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (CHAR_COMMENT_START == char_type) {
            rc = state_insert(validate, STATE_COMMENT);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if ((validate->prev_setting_complete) &&
                   (CHAR_SEMICOLON == char_type)) {
            validate->prev_setting_complete = false;
        } else if (CHAR_INVISIBLE != char_type) {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(STATE_NONE),
                           state_to_expected(STATE_NONE));
        }
    }

    return rc;
}

static int state_setting_cb(struct validate *validate, struct state *last_state,
                            char ch, enum char_type_e char_type)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if ((false == last_state->finished) &&
            ((CHAR_LETTER == char_type) || (CHAR_NUM == char_type) ||
             (CHAR_SPECIAL == char_type))) {
            last_state->char_num++;
        } else if (CHAR_ASSIGN == char_type) {
            last_state->finished = true;
            rc = state_insert(validate, STATE_ASSIGN);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (CHAR_INVISIBLE == char_type) {
            last_state->finished = true;
        } else {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_assign_cb(struct validate *validate, struct state *last_state,
                           char ch, enum char_type_e char_type)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if (CHAR_DOUBLE_QUOTES == char_type) {
            rc = state_insert(validate, STATE_VALUE_STR_START);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if ((CHAR_NUM == char_type) && ('0' == ch)) {
            rc = state_insert(validate, STATE_VALUE_0XH_0);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (CHAR_NUM == char_type) {
            rc = state_insert(validate, STATE_VALUE_NUMBER);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (('t' == ch) || ('T' == ch)) {
            rc = state_insert(validate, STATE_VALUE_BOOL_TRUE);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (('f' == ch) || ('F' == ch)) {
            rc = state_insert(validate, STATE_VALUE_BOOL_FALSE);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (CHAR_GROUP_START == char_type) {
            rc = state_insert(validate, STATE_GROUP_START);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (CHAR_LIST_START == char_type) {
            validate->list_is_emty = true;
            rc = state_insert(validate, STATE_LIST_START);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (CHAR_INVISIBLE != char_type) {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_value_0xh_0_cb(struct validate *validate,
                                struct state *last_state, char ch,
                                enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if ((CHAR_LETTER == char_type) && (('x' == ch) || ('X' == ch))) {
            last_state->flag = STATE_VALUE_0XH_X;
        } else if ((CHAR_LETTER == char_type) && ('L' == ch)) {
            last_state->flag = STATE_VALUE_LNUMBER;
        } else if ((CHAR_NUM == char_type)) {
            last_state->flag = STATE_VALUE_NUMBER;
        } else if ((CHAR_INVISIBLE == char_type) ||
                   (CHAR_SEMICOLON == char_type)) {
            if ((CHAR_INVISIBLE == char_type)) {
                validate->prev_setting_complete = true;
            }

            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            assert(STATE_ASSIGN == state_assign->flag);

            state_setting =
                TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
            assert(NULL != state_setting);
            assert(STATE_SETTING == state_setting->flag);

            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
            TAILQ_REMOVE(&validate->tailq_head, state_assign, tailq_entries);
            state_free(state_assign);
            TAILQ_REMOVE(&validate->tailq_head, state_setting, tailq_entries);
            state_free(state_setting);
        } else {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_value_number_cb(struct validate *validate,
                                 struct state *last_state, char ch,
                                 enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if (CHAR_NUM == char_type) {
            last_state->flag = STATE_VALUE_NUMBER;
        } else if ((CHAR_LETTER == char_type) && ('L' == ch)) {
            last_state->flag = STATE_VALUE_LNUMBER;
        } else if ((CHAR_INVISIBLE == char_type) ||
                   (CHAR_SEMICOLON == char_type)) {
            if ((CHAR_INVISIBLE == char_type)) {
                validate->prev_setting_complete = true;
            }
            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            assert(STATE_ASSIGN == state_assign->flag);

            state_setting =
                TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
            assert(NULL != state_setting);
            assert(STATE_SETTING == state_setting->flag);

            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
            TAILQ_REMOVE(&validate->tailq_head, state_assign, tailq_entries);
            state_free(state_assign);
            TAILQ_REMOVE(&validate->tailq_head, state_setting, tailq_entries);
            state_free(state_setting);
        } else {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_value_lnumber_cb(struct validate *validate,
                                  struct state *last_state, char ch,
                                  enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if ((CHAR_INVISIBLE == char_type) || (CHAR_SEMICOLON == char_type)) {
            if ((CHAR_INVISIBLE == char_type)) {
                validate->prev_setting_complete = true;
            }
            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            assert(STATE_ASSIGN == state_assign->flag);

            state_setting =
                TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
            assert(NULL != state_setting);
            assert(STATE_SETTING == state_setting->flag);

            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
            TAILQ_REMOVE(&validate->tailq_head, state_assign, tailq_entries);
            state_free(state_assign);
            TAILQ_REMOVE(&validate->tailq_head, state_setting, tailq_entries);
            state_free(state_setting);
        } else {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_value_0xh_x_cb(struct validate *validate,
                                struct state *last_state, char ch,
                                enum char_type_e char_type)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if (CHAR_IS_HEXA(char_type, ch)) {
            last_state->flag = STATE_VALUE_0XH_H;
        } else {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_value_0xh_h_cb(struct validate *validate,
                                struct state *last_state, char ch,
                                enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if (CHAR_IS_HEXA(char_type, ch)) {
            last_state->char_num++;
        } else if ((CHAR_LETTER == char_type) && ('L' == ch)) {
            last_state->flag = STATE_VALUE_0XH_L;
        } else if ((CHAR_INVISIBLE == char_type) ||
                   (CHAR_SEMICOLON == char_type)) {
            if ((CHAR_INVISIBLE == char_type)) {
                validate->prev_setting_complete = true;
            }
            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            assert(STATE_ASSIGN == state_assign->flag);

            state_setting =
                TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
            assert(NULL != state_setting);
            assert(STATE_SETTING == state_setting->flag);

            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
            TAILQ_REMOVE(&validate->tailq_head, state_assign, tailq_entries);
            state_free(state_assign);
            TAILQ_REMOVE(&validate->tailq_head, state_setting, tailq_entries);
            state_free(state_setting);
        } else {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_value_0xh_l_cb(struct validate *validate,
                                struct state *last_state, char ch,
                                enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if ((CHAR_INVISIBLE == char_type) || (CHAR_SEMICOLON == char_type)) {
            if ((CHAR_INVISIBLE == char_type)) {
                validate->prev_setting_complete = true;
            }
            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            assert(STATE_ASSIGN == state_assign->flag);

            state_setting =
                TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
            assert(NULL != state_setting);
            assert(STATE_SETTING == state_setting->flag);

            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
            TAILQ_REMOVE(&validate->tailq_head, state_assign, tailq_entries);
            state_free(state_assign);
            TAILQ_REMOVE(&validate->tailq_head, state_setting, tailq_entries);
            state_free(state_setting);
        } else {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_value_str_start_cb(struct validate *validate,
                                    struct state *last_state,
                                    __attribute__((unused)) char ch,
                                    enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if (CHAR_DOUBLE_QUOTES == char_type) {
            validate->prev_setting_complete = true;

            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            assert(STATE_ASSIGN == state_assign->flag);

            state_setting =
                TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
            assert(NULL != state_setting);
            assert(STATE_SETTING == state_setting->flag);

            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
            TAILQ_REMOVE(&validate->tailq_head, state_assign, tailq_entries);
            state_free(state_assign);
            TAILQ_REMOVE(&validate->tailq_head, state_setting, tailq_entries);
            state_free(state_setting);
        } else if (CHAR_ESCAPE == char_type) {
            last_state->flag = STATE_VALUE_STR_CNTNT;
            last_state->escaped = true;
        } else {
            last_state->flag = STATE_VALUE_STR_CNTNT;
        }
    }

    return rc;
}

static int state_value_str_cntnt_cb(struct validate *validate,
                                    struct state *last_state,
                                    __attribute__((unused)) char ch,
                                    enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if ((false == last_state->escaped) &&
            (CHAR_DOUBLE_QUOTES == char_type)) {
            validate->prev_setting_complete = true;

            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            assert(STATE_ASSIGN == state_assign->flag);

            state_setting =
                TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
            assert(NULL != state_setting);
            assert(STATE_SETTING == state_setting->flag);

            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
            TAILQ_REMOVE(&validate->tailq_head, state_assign, tailq_entries);
            state_free(state_assign);
            TAILQ_REMOVE(&validate->tailq_head, state_setting, tailq_entries);
            state_free(state_setting);
        } else {
            if (true == last_state->escaped) {
                last_state->escaped = false;
            } else if (CHAR_ESCAPE == char_type) {
                last_state->escaped = true;
            }
            last_state->char_num++;
        }
    }

    return rc;
}

static int state_value_bool_true_cb(struct validate *validate,
                                    struct state *last_state, char ch,
                                    enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;
    char tmp = '\0';

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if ((last_state->char_num < strlen(true_str)) &&
            (tmp = true_str[last_state->char_num], CHAR_CASE_CMP(ch, tmp))) {
            last_state->char_num++;
        } else if ((last_state->char_num == strlen(true_str)) &&
                   ((CHAR_INVISIBLE == char_type) ||
                    (CHAR_SEMICOLON == char_type))) {
            if ((CHAR_INVISIBLE == char_type)) {
                validate->prev_setting_complete = true;
            }

            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            assert(STATE_ASSIGN == state_assign->flag);

            state_setting =
                TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
            assert(NULL != state_setting);
            assert(STATE_SETTING == state_setting->flag);

            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
            TAILQ_REMOVE(&validate->tailq_head, state_assign, tailq_entries);
            state_free(state_assign);
            TAILQ_REMOVE(&validate->tailq_head, state_setting, tailq_entries);
            state_free(state_setting);
        } else {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_value_bool_false_cb(struct validate *validate,
                                     struct state *last_state, char ch,
                                     enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;
    char tmp = '\0';

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if ((last_state->char_num < strlen(false_str)) &&
            (tmp = false_str[last_state->char_num], CHAR_CASE_CMP(ch, tmp))) {
            last_state->char_num++;
        } else if ((last_state->char_num == strlen(false_str)) &&
                   ((CHAR_INVISIBLE == char_type) ||
                    (CHAR_SEMICOLON == char_type))) {
            if ((CHAR_INVISIBLE == char_type)) {
                validate->prev_setting_complete = true;
            }

            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            assert(STATE_ASSIGN == state_assign->flag);

            state_setting =
                TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
            assert(NULL != state_setting);
            assert(STATE_SETTING == state_setting->flag);

            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
            TAILQ_REMOVE(&validate->tailq_head, state_assign, tailq_entries);
            state_free(state_assign);
            TAILQ_REMOVE(&validate->tailq_head, state_setting, tailq_entries);
            state_free(state_setting);
        } else {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_group_start_cb(struct validate *validate,
                                struct state *last_state, char ch,
                                enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if (CHAR_LETTER == char_type) {
            rc = state_insert(validate, STATE_SETTING);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (CHAR_COMMENT_START == char_type) {
            rc = state_insert(validate, STATE_COMMENT);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (CHAR_GROUP_END == char_type) {
            validate->prev_setting_complete = true;

            state_assign =
                TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
            assert(NULL != state_assign);
            if (STATE_ASSIGN == state_assign->flag) {
                state_setting =
                    TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
                assert(NULL != state_setting);
                assert(STATE_SETTING == state_setting->flag);

                TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
                state_free(last_state);
                TAILQ_REMOVE(&validate->tailq_head, state_assign,
                             tailq_entries);
                state_free(state_assign);
                TAILQ_REMOVE(&validate->tailq_head, state_setting,
                             tailq_entries);
                state_free(state_setting);
            } else {
                TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
                state_free(last_state);
            }
        } else if ((validate->prev_setting_complete) &&
                   (CHAR_SEMICOLON == char_type)) {
            validate->prev_setting_complete = false;
        } else if (CHAR_INVISIBLE != char_type) {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_list_start_cb(struct validate *validate,
                               struct state *last_state, char ch,
                               enum char_type_e char_type)
{
    int rc = 0;
    struct state *state_assign = NULL;
    struct state *state_setting = NULL;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if (CHAR_GROUP_START == char_type) {
            if ((validate->list_is_emty ||
                 validate->prev_setting_complete == false)) {
                validate->list_is_emty = false;
                rc = state_insert(validate, STATE_GROUP_START);
                if (RC_ISNOTOK(rc)) {
                    LOG_ERROR("Failed to create and insert state: %d", rc);
                }
            } else {
                VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. "
                               "List items are divided by comma ',' but NOT "
                               "ended by comma ','. Please add comma ',' "
                               "character before '%s' '%c' ",
                               char_type_to_str(char_type), ch,
                               state_to_str(last_state->flag),
                               char_type_to_str(char_type), ch);
            }
        } else if (CHAR_COMMENT_START == char_type) {
            rc = state_insert(validate, STATE_COMMENT);
            if (RC_ISNOTOK(rc)) {
                LOG_ERROR("Failed to create and insert state: %d", rc);
            }
        } else if (CHAR_LIST_END == char_type) {
            if (validate->prev_setting_complete == true ||
                validate->list_is_emty) {
                validate->prev_setting_complete = true;

                state_assign =
                    TAILQ_PREV(last_state, tailq_state_head, tailq_entries);
                assert(NULL != state_assign);
                assert(STATE_ASSIGN == state_assign->flag);

                state_setting =
                    TAILQ_PREV(state_assign, tailq_state_head, tailq_entries);
                assert(NULL != state_setting);
                assert(STATE_SETTING == state_setting->flag);

                TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
                state_free(last_state);
                TAILQ_REMOVE(&validate->tailq_head, state_assign,
                             tailq_entries);
                state_free(state_assign);
                TAILQ_REMOVE(&validate->tailq_head, state_setting,
                             tailq_entries);
                state_free(state_setting);
            } else {
                VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                               char_type_to_str(char_type), ch,
                               state_to_str(last_state->flag),
                               "Expected is list content. List items are "
                               "divided by comma ',' but NOT ended by comma ','"
                               ". Please remove previous comma ',' "
                               "character or add one more list item before "
                               "'list end character' ')'");
            }
        } else if ((validate->prev_setting_complete) &&
                   (CHAR_LIST_ITEM_DELIMITER == char_type)) {
            validate->prev_setting_complete = false;
        } else if (CHAR_INVISIBLE != char_type) {
            VALIDATE_ERROR("unexpected '%s' '%c' when parsing '%s'. %s",
                           char_type_to_str(char_type), ch,
                           state_to_str(last_state->flag),
                           state_to_expected(last_state->flag));
        }
    }

    return rc;
}

static int state_comment_cb(struct validate *validate, struct state *last_state,
                            char ch,
                            __attribute__((unused)) enum char_type_e char_type)
{
    int rc = 0;

    PARAM_NULL_CHECK(rc, validate, last_state);

    if (RC_ISOK(rc)) {
        if (('\n' == ch) || ('\r' == ch)) {
            TAILQ_REMOVE(&validate->tailq_head, last_state, tailq_entries);
            state_free(last_state);
        }
    }

    return rc;
}

/**
 * callback array pointer initialization
 *
 * @param char_types list of types of characters to be initialized
 * @return 0 on success, -1 on error
 */
static int validate_char_types_init(enum char_type_e *char_types)
{
    int rc = 0;
    size_t i = 0;
    char tmp = '\0';

    PARAM_NULL_CHECK(rc, char_types);

    if (RC_ISOK(rc)) {
        for (i = 0; i < CHAR_TYPES_NUM; i++) {
            char_types[i] = CHAR_OTHER;
        }

        for (i = 32; i < 127; i++) {
            char_types[i] = CHAR_NORMAL;
        }

        for (i = 65; i <= 90; i++) {
            char_types[i] = CHAR_LETTER;
        }

        for (i = 97; i <= 122; i++) {
            char_types[i] = CHAR_LETTER;
        }

        for (i = 48; i < 58; i++) {
            char_types[i] = CHAR_NUM;
        }

        tmp = '\\';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_ESCAPE);
        tmp = '-';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_SPECIAL);
        tmp = '_';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_SPECIAL);
        tmp = '\n';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_INVISIBLE);
        tmp = '\r';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_INVISIBLE);
        tmp = '\t';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_INVISIBLE);
        tmp = ' ';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_INVISIBLE);
        tmp = ':';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_ASSIGN);
        tmp = '=';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_ASSIGN);
        tmp = ';';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_SEMICOLON);
        tmp = '{';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_GROUP_START);
        tmp = '}';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_GROUP_END);
        tmp = '(';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_LIST_START);
        tmp = ')';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_LIST_END);
        tmp = ',';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_LIST_ITEM_DELIMITER);
        tmp = '"';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_DOUBLE_QUOTES);
        tmp = '#';
        ASSIGN_CHAR_TYPE(char_types, tmp, CHAR_COMMENT_START);
    }

    return rc;
}

static int validate_run(struct validate *validate)
{
    int rc = 0;
    char ch = '\0';
    struct state *state = NULL;
    enum char_type_e char_types[CHAR_TYPES_NUM];
    enum char_type_e char_type;

    PARAM_NULL_CHECK(rc, validate, validate->file_path, validate->file);

    if (RC_ISOK(rc)) {
        rc = validate_char_types_init(char_types);
        if (RC_ISNOTOK(rc)) {
            LOG_ERROR("Failed: %d", rc);
        }
    }

    if (RC_ISOK(rc)) {
        assert(TAILQ_EMPTY(&validate->tailq_head));
    }

    if (RC_ISOK(rc)) {
        while (1 == (rc = validate_get_char(validate, &ch))) {
            state = TAILQ_LAST(&validate->tailq_head, tailq_state_head);
            char_type = char_to_type(char_types, (uint8_t *)&ch);

            /*LOG_DEBUG("Reading <%s> line <%zu> position <%zu>: '%s' '%c'. "
                      "Currently parsing state: '%s'. %s ",
                      validate->file_path, validate->line_num,
                      validate->line_pos, char_type_to_str(char_type), ch,
                      state_to_str(state ? state->flag : STATE_NONE),
                      state_to_expected(state ? state->flag : STATE_NONE));*/

            if (NULL == state) {
                rc = state_cb[STATE_NONE](validate, state, ch, char_type);
            } else {
                assert(state->flag > STATE_NONE && state->flag < STATE_LAST);
                rc = state_cb[state->flag](validate, state, ch, char_type);
            }

            if (RC_ISNOTOK(rc)) {
                rc = -1;
                break;
            }
        }

        if (RC_ISOK(rc)) {
            state = TAILQ_LAST(&validate->tailq_head, tailq_state_head);

            /* if unfinished parsing state has been found report error */
            if (NULL != state) {
                VALIDATE_ERROR("unexpected end of file when parsing '%s'. %s",
                               state_to_str(state->flag),
                               state_to_expected(state->flag));
            }
        }
    }

    return rc;
}

/**
 * @brief configuration validation
 */
int cfg_validate(const char *file_path, char *error, size_t error_size)
{
    int rc = 0;
    struct validate validate;

    rc = validate_init(&validate, file_path, error, error_size);
    if (RC_ISNOTOK(rc)) {
        LOG_ERROR("Configuration validation initialization failed: %d", rc);
    }

    if (RC_ISOK(rc)) {
        rc = validate_run(&validate);
        if (RC_ISNOTOK(rc)) {
            if (true == validate.syntax_error) {
                LOG_ERROR("Configuration validation syntax error: %d: %s", rc,
                          validate.error);
                rc = 1;
            } else {
                LOG_ERROR(
                    "Configuration validation internal error occurred: %d", rc);
            }
        }
    }

    validate_deinit(&validate);

    return rc;
}
