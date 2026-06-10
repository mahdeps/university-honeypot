# -*- coding: utf-8 -*-
"""
Dynamic data injection for the cloned portal pages.

The captured pages carry one real account's tables (grades, finances, courses,
schedule). We tokenize those table regions once (see tools/_tokenize), then at
serve time regenerate them from the decoy DB for whoever is logged in — turning
the static clone into a live, per-student system driven by the big database.
"""
from . import decoy_db


def _conn():
    return decoy_db._connect()


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# ---- grades / transcript ----------------------------------------------------

def grades_html(sid):
    conn = _conn()
    try:
        rows = conn.execute(
            "SELECT e.course_code, c.title, c.credits, e.coursework, e.final, "
            "e.total, e.grade, e.semester "
            "FROM enrollments e JOIN courses c ON c.code = e.course_code "
            "WHERE e.student_id = ? ORDER BY e.semester", (sid,)).fetchall()
    finally:
        conn.close()
    # group by semester (keep first-seen order)
    sems, order = {}, []
    for r in rows:
        if r["semester"] not in sems:
            sems[r["semester"]] = []
            order.append(r["semester"])
        sems[r["semester"]].append(r)

    cum_pts = cum_cr = 0.0
    out = []
    for sem in order:
        items = sems[sem]
        sem_pts = sum(x["total"] * x["credits"] for x in items)
        sem_cr = sum(x["credits"] for x in items)
        cum_pts += sem_pts; cum_cr += sem_cr
        sem_avg = sem_pts / sem_cr if sem_cr else 0
        cum_avg = cum_pts / cum_cr if cum_cr else 0
        body = []
        for x in items:
            body.append(
                '<tbody><tr>'
                f'<td data-th="رقم المساق"><span class="bt-content">{_esc(x["course_code"])}</span></td>'
                f'<td data-th="اسم المساق"><span class="bt-content">{_esc(x["title"])}</span></td>'
                f'<td data-th="ع الساعات"><span class="bt-content">{x["credits"]}</span></td>'
                f'<td data-th="اعمال الفصل"><span class="bt-content">{x["coursework"]}</span></td>'
                f'<td data-th="العلامة النصفية"><span class="bt-content">{max(0, x["coursework"]-10)}</span></td>'
                f'<td data-th="العلامة النهائية"><span class="bt-content">{x["final"]}</span></td>'
                f'<td data-th="المجموع"><span class="bt-content">{x["total"]}</span></td>'
                f'<td data-th="اعتماد الدرجة"><span class="bt-content"><b>{_esc(x["grade"])}</b></span></td>'
                '</tr></tbody>')
        out.append(
            f'<h4 class="btn btn-block bg-info text-white mb-0">{_esc(sem)}</h4>'
            '<table class="table responsive_table mb-0"><thead><tr>'
            '<th>رقم المساق</th><th>اسم المساق</th><th>ع الساعات</th><th>اعمال الفصل</th>'
            '<th>العلامة النصفية</th><th>العلامة النهائية</th><th>المجموع</th><th>اعتماد الدرجة</th>'
            '</tr></thead>' + "".join(body) + '</table>'
            '<table class="table table-hover mb-0"><tbody>'
            '<tr class="bg-success text-white noresponsive"><td></td><td></td><td></td>'
            f'<td>المعدل الفصلي: {sem_avg:.2f} % </td>'
            f'<td>المعدل التراكمي: {cum_avg:.2f} % </td></tr></tbody></table><br>')
    return "".join(out) if out else '<p class="text-muted">لا توجد درجات.</p>'


# ---- finances ---------------------------------------------------------------

def _sem_no(sem):
    # "2023/2024 الأول" -> "20231"
    term = {"الأول": "1", "الثاني": "2", "الصيفي": "3"}
    yr = sem.split("/")[0]
    t = next((v for k, v in term.items() if k in sem), "1")
    return yr + t


def finance_html(sid):
    conn = _conn()
    try:
        fees = conn.execute(
            "SELECT semester, description, amount, type FROM fees WHERE student_id=? "
            "ORDER BY semester", (sid,)).fetchall()
        pays = conn.execute(
            "SELECT date, amount, method, reference FROM payments WHERE student_id=? "
            "ORDER BY date", (sid,)).fetchall()
    finally:
        conn.close()
    sems, order = {}, []
    for f in fees:
        if f["semester"] not in sems:
            sems[f["semester"]] = []; order.append(f["semester"])
        sems[f["semester"]].append(f)
    pays = list(pays); pj = 0
    running = 0.0
    out = []
    import random
    for sem in order:
        rows = []; i = 1
        for f in sems[sem]:
            running += f["amount"]
            rows.append(
                '<tr>'
                f'<td data-th="م"><span class="bt-content">{i}</span></td>'
                f'<td data-th="رقم السجل"><span class="bt-content">{random.randint(30000000,39999999)}</span></td>'
                f'<td data-th="مدين"><span class="bt-content">{f["amount"]:.2f}</span></td>'
                '<td data-th="دائن"><span class="bt-content">0</span></td>'
                f'<td data-th="التاريخ"><span class="bt-content">{random.randint(1,28):02d}/0{random.randint(1,9)}/{sem.split("/")[1][:4]}</span></td>'
                f'<td data-th="البيان"><span class="bt-content">{_esc(f["description"])}</span></td></tr>')
            i += 1
        for _ in range(min(2, len(pays) - pj)):
            p = pays[pj]; pj += 1
            running -= p["amount"]
            rows.append(
                '<tr>'
                f'<td data-th="م"><span class="bt-content">{i}</span></td>'
                f'<td data-th="رقم السجل"><span class="bt-content">{_esc(p["reference"])}</span></td>'
                '<td data-th="مدين"><span class="bt-content">0</span></td>'
                f'<td data-th="دائن"><span class="bt-content">{p["amount"]:.2f}</span></td>'
                f'<td data-th="التاريخ"><span class="bt-content">{_esc(p["date"])}</span></td>'
                f'<td data-th="البيان"><span class="bt-content">دفعة من الرسوم - {_esc(p["method"])}</span></td></tr>')
            i += 1
        out.append(
            '<table class="table table-hover mb-0 noresponsive"><tbody>'
            '<tr class="bg-info text-white tsx"><td colspan="6">'
            f'<span>رقم الفصل: {_sem_no(sem)}</span><span> {_esc(sem)}</span>'
            f'<span>رصيد التراكمي: {running:.2f}</span></td></tr></tbody></table>'
            '<div class="table-responsive"><table class="table responsive_table mb-0">'
            '<thead><tr class="bg-secondary text-white"><td>م</td><td>رقم السجل</td>'
            '<td>مدين</td><td>دائن</td><td>التاريخ</td><td>البيان</td></tr></thead><tbody>'
            + "".join(rows) + '</tbody></table></div><br><br>')
    return "".join(out) if out else '<p class="text-muted">لا توجد حركات مالية.</p>'


# ---- current courses (registered + weekly schedule) -------------------------

def _current_courses(conn, sid):
    latest = conn.execute("SELECT semester FROM enrollments WHERE student_id=? "
                          "ORDER BY semester DESC LIMIT 1", (sid,)).fetchone()
    if not latest:
        return []
    return conn.execute(
        "SELECT e.course_code, c.title, c.credits, "
        " (SELECT i.full_name FROM sections s JOIN instructors i ON i.instructor_id=s.instructor_id "
        "  WHERE s.course_code=e.course_code LIMIT 1) AS instr, "
        " (SELECT room FROM sections s WHERE s.course_code=e.course_code LIMIT 1) AS room, "
        " (SELECT day  FROM sections s WHERE s.course_code=e.course_code LIMIT 1) AS day, "
        " (SELECT time FROM sections s WHERE s.course_code=e.course_code LIMIT 1) AS time "
        "FROM enrollments e JOIN courses c ON c.code=e.course_code "
        "WHERE e.student_id=? AND e.semester=? LIMIT 9",
        (sid, latest["semester"])).fetchall()


def registered_html(sid):
    conn = _conn()
    try:
        cs = _current_courses(conn, sid)
    finally:
        conn.close()
    rows = []
    for c in cs:
        rows.append(
            '<tr>'
            f'<td data-th="رقم المساق"><span class="bt-content">{_esc(c["course_code"])}</span></td>'
            f'<td data-th="اسم المساق"><span class="bt-content">{_esc(c["title"])}</span></td>'
            '<td data-th="الشعبة"><span class="bt-content">301</span></td>'
            f'<td data-th="اسم المدرس"><span class="bt-content">{_esc(c["instr"] or "—")}</span></td>'
            '<td data-th="طبيعة الإمتحان"><span class="bt-content">تحريري</span></td>'
            '<td data-th="الحضور"><span class="bt-content">منتظم</span></td></tr>')
    body = ("".join(rows) if rows else
            '<tr><td colspan="6" class="text-center text-muted">لا توجد مساقات مسجلة.</td></tr>')
    return ('<table class="table responsive_table mb-0"><thead class="thead-dark">'
            '<tr class="bg-info text-white"><td>رقم المساق</td><td>اسم المساق</td>'
            '<td>الشعبة</td><td>اسم المدرس</td><td>طبيعة الإمتحان</td><td>الحضور</td>'
            '</tr></thead><tbody>' + body + '</tbody></table>')


_DAYCOLS = ["السبت", "الاحد", "الاثنين", "الثلاثاء", "الاربعاء", "الخميس"]
_DAYKEYS = {"السبت": "السبت", "الاحد": "الأحد", "الاثنين": "الاثنين",
            "الثلاثاء": "الثلاثاء", "الاربعاء": "الأربعاء", "الخميس": "الخميس"}


def schedule_html(sid):
    conn = _conn()
    try:
        cs = _current_courses(conn, sid)
    finally:
        conn.close()
    rows = []
    for c in cs:
        day = c["day"] or ""
        tm = c["time"] or ""
        cells = ""
        for col in _DAYCOLS:
            hit = _DAYKEYS[col] in day
            cells += f'<td data-th="{col}"><span class="bt-content">{tm if hit else ""}</span></td>'
        rows.append(
            '<tr>'
            f'<td data-th="رقم المساق"><span class="bt-content">{_esc(c["course_code"])}</span></td>'
            f'<td data-th="اسم المساق"><span class="bt-content">{_esc(c["title"])}</span></td>'
            '<td data-th="الشعبة"><span class="bt-content">301</span></td>'
            f'<td data-th="القاعة"><span class="bt-content">{_esc(c["room"] or "—")}</span></td>'
            + cells + '</tr>')
    body = ("".join(rows) if rows else
            '<tr><td colspan="10" class="text-center text-muted">لا يوجد جدول.</td></tr>')
    head = "".join(f"<td>{d}</td>" for d in
                   ["رقم المساق", "اسم المساق", "الشعبة", "القاعة"] + _DAYCOLS)
    return ('<table class="table responsive_table mb-0"><thead class="thead-dark">'
            '<tr class="bg-info text-white">' + head + '</tr></thead><tbody>'
            + body + '</tbody></table>')


# ---- student profile fields (بيانات الطالب) ---------------------------------

import re as _re
import random as _random

_MOTHER_NAMES = "فاطمة عائشة مريم خديجة زينب نور هدى سمر منى أمل وفاء سعاد نعمة سهام".split()


def _attr(v):
    return str(v).replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")


def _set_input(html, el_id, value):
    def repl(m):
        tag = m.group(0)
        if 'value="' in tag:
            return _re.sub(r'value="[^"]*"', 'value="%s"' % value, tag, count=1)
        return tag[:-1] + ' value="%s">' % value
    return _re.sub(r'<input\b[^>]*\bid="%s"[^>]*>' % _re.escape(el_id), repl, html, count=1)


def _set_select(html, el_id, text):
    m = _re.search(r'(<select\b[^>]*\bid="%s"[^>]*>)(.*?)(</select>)' % _re.escape(el_id),
                   html, _re.S)
    if not m:
        return html
    inner = _re.sub(r'(<option[^>]*\bselected[^>]*>)[^<]*',
                    lambda mm: mm.group(1) + text, m.group(2), count=1)
    return html[:m.start(2)] + inner + html[m.end(2):]


def student_info_fields(html, sid):
    conn = _conn()
    try:
        s = conn.execute("SELECT * FROM students WHERE student_id=?", (sid,)).fetchone()
    finally:
        conn.close()
    if not s:
        return html
    parts = (s["full_name"].split() + ["", "", "", ""])[:4]
    dob = s["dob"]
    try:
        y, m, d = dob.split("-"); dob = f"{d}/{m}/{y}"
    except Exception:
        pass
    rnd = _random.Random(sid)
    inputs = {
        "ContentPlaceHolder1_V_STDNAME1": parts[0], "ContentPlaceHolder1_V_STDNAME2": parts[1],
        "ContentPlaceHolder1_V_STDNAME3": parts[2], "ContentPlaceHolder1_V_STDNAME4": parts[3],
        "ContentPlaceHolder1_V_STDENAME1": "", "ContentPlaceHolder1_V_STDENAME2": "",
        "ContentPlaceHolder1_V_STDENAME3": "", "ContentPlaceHolder1_V_STDENAME4": "",
        "ContentPlaceHolder1_V_STDGUARDIAN": parts[2] or parts[1],
        "ContentPlaceHolder1_V_DOB": dob,
        "ContentPlaceHolder1_V_STDID": s["national_id"],
        "ContentPlaceHolder1_V_MOTHERNAME": rnd.choice(_MOTHER_NAMES),
        "ContentPlaceHolder1_V_MOTHER_WORK_DESC": "ربة منزل",
        "ContentPlaceHolder1_V_FATHER_WORK_DESC": "موظف",
        "ContentPlaceHolder1_V_FAMILY_COUNT": str(rnd.randint(3, 9)),
        "ContentPlaceHolder1_V_UNI_COUNT": "1",
        "ContentPlaceHolder1_V_MOAQ_COUNT": str(rnd.randint(0, 3)),
        "ContentPlaceHolder1_V_POBOX": "0",
        "ContentPlaceHolder1_V_PHONE": "",
        "ContentPlaceHolder1_V_MOBILE": s["phone"],
        "ContentPlaceHolder1_V_EMERGENCY": "059" + "".join(str(rnd.randint(0, 9)) for _ in range(7)),
        "ContentPlaceHolder1_V_EMAIL": s["email"],
        "ContentPlaceHolder1_V_ROOMS_CNT": str(rnd.randint(2, 5)),
    }
    selects = {
        "ContentPlaceHolder1_V_CITY": s["city"], "ContentPlaceHolder1_V_DISTRICT": "غزة",
        "ContentPlaceHolder1_V_BP": "فلسطين - غزة", "ContentPlaceHolder1_V_PART": "—",
        "ContentPlaceHolder1_V_STREET": "—", "ContentPlaceHolder1_V_DISPLACEMENT": "لا يوجد",
        "ContentPlaceHolder1_V_DISPLACEMENT_TYPE": "منزل",
        "ContentPlaceHolder1_V_HOUSE_DESTROY": "لا يوجد",
        "ContentPlaceHolder1_V_PARENT_EXIST": "كلاهما على قيد الحياة",
        "ContentPlaceHolder1_V_W_BREADWINNER_CHANGED": "لا",
        "ContentPlaceHolder1_V_BREADWINNER_REASON_NO": "—",
        # family / housing / devices — neutral defaults, identical for every student
        "ContentPlaceHolder1_V_GUARDIAN_KINSHIP": "الأب",
        "ContentPlaceHolder1_V_MOTHER_WORK": "لا يعمل",
        "ContentPlaceHolder1_V_FATHER_WORK": "يعمل",
        "ContentPlaceHolder1_V_SOCIALAID": "لا يوجد مساعدات",
        "ContentPlaceHolder1_V_HOME_TYPE": "ملك",
        "ContentPlaceHolder1_V_HOME_NATURE": "باطون",
        "ContentPlaceHolder1_V_HOME_INDEPENDENCE": "العائلة مستقلة في السكن",
        "ContentPlaceHolder1_V_HOME_furniture": "متوسط",
        "ContentPlaceHolder1_V_HOME_EXTRA": "لا", "ContentPlaceHolder1_V_HOME_LAND": "لا",
        "ContentPlaceHolder1_V_PSYCHOLOGICAL_SUPPORT": "لا",
        "ContentPlaceHolder1_V_ACCESS_INTERNET_MEAN": "نقطة انترنت",
        "ContentPlaceHolder1_V_HAVE_LAPTOP": "لا",
        "ContentPlaceHolder1_V_HAVE_SMART_DEVICE": "لا",
        "ContentPlaceHolder1_V_HAVE_EWALLET": "لا",
        "ContentPlaceHolder1_V_EWALLET_TYPE": "—",
    }
    for k, v in inputs.items():
        html = _set_input(html, k, _attr(v))
    for k, v in selects.items():
        html = _set_select(html, k, _esc(v))
    return html


# ---- dispatcher -------------------------------------------------------------

_TOKENS = {
    "transcript.html": [("<!--HP:GRADES-->", grades_html)],
    "financial_profile.html": [("<!--HP:FINANCE-->", finance_html)],
    "registered_subjects.html": [("<!--HP:REGISTERED-->", registered_html)],
    "semester_table.html": [("<!--HP:SCHEDULE-->", schedule_html)],
}

_PAGE_FUNCS = {
    "student_info.html": student_info_fields,
    "assistance_request.html": student_info_fields,   # same personal fields
}


def fill(filename, html, sid):
    for token, gen in _TOKENS.get(filename, []):
        if token in html:
            html = html.replace(token, gen(sid))
    fn = _PAGE_FUNCS.get(filename)
    if fn and sid:
        html = fn(html, sid)
    return html
