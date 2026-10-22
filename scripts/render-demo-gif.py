#!/usr/bin/env python3
"""Render docs/assets/safepush-demo.gif from REAL SafePush output.

Every hook decision and scan line in the GIF is produced by running dist/cli.mjs against a
temporary project with synthetic credentials. Agent actions are shown as the PreToolUse
events Claude Code sends to the hook; this is not a screenshot of Claude Code.

Requirements: Python 3 with Pillow, ffmpeg, Node.js 22+, Git, and `npm run build` first.
Usage: python3 scripts/render-demo-gif.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "dist", "cli.mjs")
OUT = os.path.join(ROOT, "docs", "assets", "safepush-demo.gif")
FAKE_KEY = "sk-proj-" + "FAKEdemoKEYnotREAL" + "0" * 12  # synthetic, clearly fake

W, H, FPS = 960, 560, 10
PAD, LINE_H, COLS = 28, 24, 78
BG, BAR, FG, DIM = (13, 17, 23), (22, 27, 34), (201, 209, 217), (125, 133, 144)
GREEN, RED, YELLOW, BLUE, PURPLE = (63, 185, 80), (248, 81, 73), (210, 153, 34), (88, 166, 255), (188, 140, 255)


def font(size, bold=False):
    names = ["DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"]
    for d in ["/usr/share/fonts/truetype/dejavu", "/Library/Fonts", "C:/Windows/Fonts"]:
        for n in names:
            p = os.path.join(d, n)
            if os.path.exists(p):
                return ImageFont.truetype(p, size)
    return ImageFont.load_default()


F, FB, FS = font(16), font(16, True), font(13)


def run(args, cwd, stdin=None):
    p = subprocess.run(["node", CLI, *args], cwd=cwd, input=stdin, capture_output=True, text=True, timeout=30)
    return p.stdout


def hook(cwd, tool, tool_input):
    event = {"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": tool, "tool_input": tool_input}
    out = run(["hook", "claude"], cwd, json.dumps(event)).strip()
    return json.loads(out)["hookSpecificOutput"] if out else None


def git(args, cwd):
    subprocess.run(["git", "-c", "user.name=demo", "-c", "user.email=demo@example.test", *args],
                   cwd=cwd, check=True, capture_output=True)


def collect():
    """Run SafePush for real and return the scenes to draw."""
    tmp = tempfile.mkdtemp(prefix="safepush-gif-")
    try:
        git(["init", "-q"], tmp)
        with open(os.path.join(tmp, ".gitignore"), "w") as f:
            f.write("node_modules/\n.env\n.env.*\n!.env.example\n")
        with open(os.path.join(tmp, "package.json"), "w") as f:
            f.write('{"dependencies":{"next":"15.0.0"}}\n')
        bad = 'const OPENAI_API_KEY = "%s";' % FAKE_KEY
        good = "const OPENAI_API_KEY = process.env.OPENAI_API_KEY;"
        deny_write = hook(tmp, "Write", {"file_path": os.path.join(tmp, "src", "openai.ts"), "content": bad + "\n"})
        allow_write = hook(tmp, "Write", {"file_path": os.path.join(tmp, "src", "openai.ts"), "content": good + "\n"})
        allow_env = hook(tmp, "Write", {"file_path": os.path.join(tmp, ".env.local"), "content": "OPENAI_API_KEY=" + FAKE_KEY + "\n"})
        deny_read = hook(tmp, "Read", {"file_path": os.path.join(tmp, ".env.local")})
        deny_noverify = hook(tmp, "Bash", {"command": 'git commit --no-verify -m "ship it"'})
        assert deny_write and deny_write["permissionDecision"] == "deny", deny_write
        assert allow_write is None and allow_env is None, (allow_write, allow_env)
        assert deny_read and deny_read["permissionDecision"] == "deny", deny_read
        assert deny_noverify and deny_noverify["permissionDecision"] == "deny", deny_noverify

        # A project with leaks for the scan scene.
        os.makedirs(os.path.join(tmp, "app"), exist_ok=True)
        with open(os.path.join(tmp, "app", "page.tsx"), "w") as f:
            f.write("const db = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n")
        os.makedirs(os.path.join(tmp, "src"), exist_ok=True)
        with open(os.path.join(tmp, "src", "openai.ts"), "w") as f:
            f.write(bad + "\n")
        with open(os.path.join(tmp, ".env.production"), "w") as f:
            f.write("STRIPE_SECRET_KEY=placeholder\n")
        git(["add", "-f", ".env.production"], tmp)
        scan = run(["scan", "."], tmp)
        for secret in (FAKE_KEY,):
            assert secret not in json.dumps([deny_write, deny_read, deny_noverify]) + scan
        return deny_write, deny_read, deny_noverify, scan
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


class Term:
    """A tiny terminal model: list of (segments, ...) lines, each segment = (text, color, bold)."""

    def __init__(self):
        self.lines = []

    def add(self, *segments):
        self.lines.append(list(segments))

    def wrap(self, text, color, indent="  ", bold=False):
        for i, part in enumerate(textwrap.wrap(text, COLS - len(indent)) or [""]):
            self.add((indent + part, color, bold))

    def render(self, caption):
        img = Image.new("RGB", (W, H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0, 0, W, 34], fill=BAR)
        for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
            d.ellipse([16 + i * 22, 11, 28 + i * 22, 23], fill=c)
        d.text((W // 2, 17), "SafePush · Claude Code hook", font=FS, fill=DIM, anchor="mm")
        max_lines = (H - 34 - PAD - 40) // LINE_H
        y = 34 + PAD // 2 + 4
        for line in self.lines[-max_lines:]:
            x = PAD
            for text, color, bold in line:
                f = FB if bold else F
                d.text((x, y), text, font=f, fill=color)
                x += d.textlength(text, font=f)
            y += LINE_H
        d.rectangle([0, H - 34, W, H], fill=BAR)
        d.text((PAD, H - 17), caption, font=FS, fill=DIM, anchor="lm")
        return img


def build_frames(deny_write, deny_read, deny_noverify, scan):
    frames = []
    caption = "Hook decisions and scan output are real SafePush output. Keys are synthetic."
    t = Term()

    def hold(seconds):
        img = t.render(caption)
        frames.extend([img] * max(1, int(seconds * FPS)))

    def type_line(prefix, text, color=FG, prefix_color=GREEN):
        t.add((prefix, prefix_color, True), ("", color, False))
        for i in range(0, len(text) + 1, 3):
            t.lines[-1][1] = (text[:i], color, False)
            frames.append(t.render(caption))
        t.lines[-1][1] = (text, color, False)

    def decision(d, label_ok="allowed"):
        if d is None:
            t.add(("  SafePush ", DIM, False), ("✓ " + label_ok, GREEN, True))
        else:
            t.add(("  SafePush ", DIM, False), ("✗ " + d["permissionDecision"].upper(), RED, True))
            first = d["permissionDecisionReason"].split("\n")[0]
            t.wrap(first, FG, "    ")

    shown_key = FAKE_KEY[:16] + "…"
    type_line("agent ", "Write src/openai.ts", BLUE, PURPLE)
    t.add(("    ", FG, False), ('const OPENAI_API_KEY = "' + shown_key + '"', YELLOW, False))
    hold(0.6)
    decision(deny_write)
    hold(2.6)
    t.add(("", FG, False))
    type_line("agent ", "Write src/openai.ts  (retry)", BLUE, PURPLE)
    t.add(("    ", FG, False), ("const OPENAI_API_KEY = process.env.OPENAI_API_KEY", GREEN, False))
    hold(0.6)
    decision(None)
    hold(1.4)
    t.add(("", FG, False))
    type_line("agent ", "Read .env.local", BLUE, PURPLE)
    hold(0.4)
    decision(deny_read)
    hold(2.2)
    t.add(("", FG, False))
    type_line("agent ", 'Bash  git commit --no-verify -m "ship it"', BLUE, PURPLE)
    hold(0.4)
    decision(deny_noverify)
    hold(2.6)

    # Scene 2: the same rules as a CLI scan.
    t = Term()
    type_line("$ ", "safepush scan .", FG, GREEN)
    hold(0.5)
    for line in scan.splitlines():
        if line.startswith("SafePush v") or line.startswith("Framework") or "finding(s)" in line:
            t.add((line, DIM, False))
        elif line.startswith("["):
            sev, rest = line.split("]", 1)
            t.add((sev + "]", RED if "HIGH" in sev else YELLOW, True), (rest, FG, False))
        elif line.startswith("  ") and not line.startswith("  Priority") and not line.startswith("  Evidence") \
                and not line.startswith("  Verify") and not line.startswith("  Why") and not line.startswith("  Fix"):
            t.add((line, DIM, False))
        else:
            continue
        frames.append(t.render(caption))
        frames.append(t.render(caption))
    hold(4.5)
    return frames


def write_gif(frames):
    tmp = tempfile.mkdtemp(prefix="safepush-frames-")
    try:
        for i, img in enumerate(frames):
            img.save(os.path.join(tmp, "f%05d.png" % i))
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        pattern = os.path.join(tmp, "f%05d.png")
        palette = os.path.join(tmp, "palette.png")
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-framerate", str(FPS), "-i", pattern,
                        "-vf", "palettegen=max_colors=64:stats_mode=full", palette], check=True)
        subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-framerate", str(FPS), "-i", pattern, "-i", palette,
                        "-lavfi", "paletteuse=dither=none:diff_mode=rectangle", "-loop", "0", OUT], check=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    if not os.path.exists(CLI):
        sys.exit("Run `npm run build` first.")
    frames = build_frames(*collect())
    write_gif(frames)
    print("%s: %d frames, %.0f KB" % (os.path.relpath(OUT, ROOT), len(frames), os.path.getsize(OUT) / 1024))
