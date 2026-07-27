"""
╔═══════════════════════════════════════════════════════════╗
║               SAMBA AUDIT LOG ANALYZER  v1.1              ║
║     GUI-приложение для анализа и визуализации логов       ║
║                                                           ║
║                                                           ║
║                       @Nicolayka                          ║
╚═══════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import platform
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime

import pandas as pd
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import seaborn as sns
import customtkinter as ctk
import warnings

import re

def strip_emoji(text):
    emoji_pattern = re.compile(
        "["
        "\U0001F600-\U0001F64F"
        "\U0001F300-\U0001F5FF"
        "\U0001F680-\U0001F6FF"
        "\U0001F1E0-\U0001F1FF"
        "\U00002702-\U000027B0"
        "\U000024C2-\U0001F251"
        "]+",
        flags=re.UNICODE
    )
    return emoji_pattern.sub('', text).strip()

_APP_META = {
    "bld": "4e69636f6c61796b61",
    "ver": "1.1",
    "chk": lambda s: bytes.fromhex(s).decode('utf-8') if s else None
}

plt.rcParams['font.sans-serif'] = ['Segoe UI Emoji', 'Segoe UI Symbol', 'DejaVu Sans', 'Arial Unicode MS']
plt.rcParams['axes.unicode_minus'] = False

warnings.filterwarnings("ignore", category=UserWarning, module="matplotlib")
warnings.filterwarnings("ignore", category=UserWarning, message=".*Glyph.*missing.*")

APP_NAME = "Samba Audit Log Analyzer"
APP_VERSION = "1.1"

def _get_author():
    try:
        return _APP_META["chk"](_APP_META["bld"])
    except:
        return "Unknown"

class SambaParser:

    LOG_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s+\S+\s+smbd_audit:\s+(?P<payload>.*)$"
    )

    ACTION_TRANSLATIONS = {
        "r":        "👁️ Чтение файла",
        "read":     "👁️ Чтение файла",
        "pread":    "👁️ Чтение файла",
        "w":        "✏️ Запись в файл",
        "write":    "✏️ Запись в файл",
        "pwrite":   "✏️ Запись в файл",
        "unlink":   "🗑️ Удаление файла",
        "rmdir":    "🗑️ Удаление папки",
        "mkdir":    "📁 Создание папки",
        "rename":   "🔄 Переименование / Перемещение",
        "open":     "📂 Открытие файла",
        "close":    "📕 Закрытие файла",
        "chmod":    "🔐 Изменение прав",
        "chown":    "👤 Смена владельца",
        "connect":  "🔗 Подключение",
        "disconnect":"❌ Отключение",
    }

    DATE_FORMATS = [
        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
    ]

    @classmethod
    def parse_file(cls, filepath, progress_callback=None):
        """Парсит лог-файл и возвращает DataFrame."""
        rows = []
        total_lines = 0
        parsed_lines = 0

        # Два паттерна для разных форматов дат
        PATTERNS = [
            # Формат: 2026-07-24 07:00:41 или 2026-07-24T07:00:41
            re.compile(
                r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)\s+\S+\s+smbd_audit:\s+(?P<payload>.*)$"
            ),
            # Формат: Jul 24 07:00:41 (syslog без года)
            re.compile(
                r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+smbd_audit:\s+(?P<payload>.*)$"
            ),
        ]

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            total_lines = sum(1 for _ in f)

        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line or "smbd_audit:" not in line:
                    continue

                # Пробуем оба паттерна
                matched = False
                for pattern in PATTERNS:
                    match = pattern.search(line)
                    if match:
                        d = match.groupdict()
                        parts = d['payload'].split('|')
                        
                        if len(parts) == 7:
                            user, ip, folder, action, status, access_flag, filepath_val = parts
                        elif len(parts) == 6:
                            user, ip, folder, action, status, filepath_val = parts
                            access_flag = ""
                        else:
                            continue

                        raw_action = action.strip().lower()
                        flag = access_flag.strip().lower() if access_flag else ""

                        if raw_action == 'open' and flag:
                            if flag == 'r':
                                action_ru = "📂 Открытие (Чтение)"
                            elif flag == 'w':
                                action_ru = "📂 Открытие (Запись)"
                            elif flag == 'rw':
                                action_ru = "📂 Открытие (Чтение/Запись)"
                            else:
                                action_ru = f" Открытие (Флаг: {flag})"
                        else:
                            action_ru = cls.ACTION_TRANSLATIONS.get(raw_action, f"⚙️ {raw_action}")

                        d['user'] = user.strip()
                        d['ip'] = ip.strip()
                        d['folder'] = folder.strip()
                        d['action_ru'] = action_ru
                        d['status_ru'] = "✅ Успешно" if status.strip().lower() in ("ok", "success") else "❌ Ошибка"
                        d['filepath'] = filepath_val.strip()
                        
                        rows.append(d)
                        parsed_lines += 1
                        matched = True
                        break  # Выходим из цикла паттернов
                
                if not matched:
                    continue  # Строка не подошла ни под один паттерн

                if progress_callback and i % 500 == 0:
                    progress_callback(i / max(total_lines, 1))

        if not rows:
            return pd.DataFrame(), parsed_lines, total_lines

        df = pd.DataFrame(rows)
        df["timestamp"] = cls._parse_timestamps(df["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)

        if progress_callback:
            progress_callback(1.0)

        return df, parsed_lines, total_lines

    @classmethod
    def _parse_timestamps(cls, timestamp_series):
        from datetime import datetime
        import pandas as pd

        result = pd.Series(pd.NaT, index=timestamp_series.index)
        current_year = datetime.now().year

        for fmt in cls.DATE_FORMATS:
            mask = result.isna()
            if not mask.any():
                break
            try:
                result[mask] = pd.to_datetime(timestamp_series[mask], format=fmt, errors="coerce")
            except Exception:
                pass

        mask = result.isna()
        if mask.any():
            parsed_syslog = []
            for ts in timestamp_series[mask]:
                try:
                    dt = datetime.strptime(f"{current_year} {ts}", "%Y %b %d %H:%M:%S")
                    parsed_syslog.append(dt)
                except Exception:
                    parsed_syslog.append(pd.NaT)
            result[mask] = parsed_syslog

        mask = result.isna()
        if mask.any():
            try:
                result[mask] = pd.to_datetime(timestamp_series[mask], errors="coerce")
            except Exception:
                pass

        return result

    @staticmethod
    def get_stats(df):
        if df.empty:
            return {}

        valid_ts = df["timestamp"].dropna()
        return {
            "total": len(df),
            "users": df["user"].nunique(),
            "ips": df["ip"].nunique(),
            "folders": df["folder"].nunique(),
            "success": (df["status_ru"] == "✅ Успешно").sum(),
            "errors": (df["status_ru"] == "❌ Ошибка").sum(),
            "time_from": str(valid_ts.min()) if len(valid_ts) else "N/A",
            "time_to": str(valid_ts.max()) if len(valid_ts) else "N/A",
            "top_user": df["user"].value_counts().idxmax() if len(df) else "N/A",
            "top_action": df["action_ru"].value_counts().idxmax() if len(df) else "N/A",
        }

class ChartBuilder:

    @staticmethod
    def build_all(df, parent_frame, dpi=100):
        import re

        def strip_emoji(text):
            emoji_pattern = re.compile(
                "["
                "\U0001F600-\U0001F64F"
                "\U0001F300-\U0001F5FF"
                "\U0001F680-\U0001F6FF"
                "\U0001F1E0-\U0001F1FF"
                "\U00002702-\U000027B0"
                "\U000024C2-\U0001F251"
                "]+", flags=re.UNICODE
            )
            return emoji_pattern.sub('', text).strip()

        for widget in parent_frame.winfo_children():
            widget.destroy()

        fig = Figure(figsize=(12, 9), dpi=dpi)
        fig.patch.set_facecolor("#2b2b2b")
        sns.set_theme(style="darkgrid")

        colors_actions = sns.color_palette("viridis", min(10, df["action_ru"].nunique()))
        colors_users = sns.color_palette("magma", min(10, df["user"].nunique()))

        ax1 = fig.add_subplot(2, 2, 1)
        action_counts = df["action_ru"].value_counts().head(10)
        clean_action_labels = [strip_emoji(str(label)) for label in action_counts.index]
        sns.barplot(
            x=action_counts.values,
            y=clean_action_labels,
            hue=clean_action_labels,
            palette=colors_actions,
            legend=False,
            ax=ax1,
        )
        ax1.set_title("Топ-10 операций", fontsize=12, fontweight="bold", color="white")
        ax1.set_xlabel("Количество", color="white")
        ax1.set_ylabel("", color="white")
        ax1.set_facecolor("#2b2b2b")
        ax1.tick_params(colors="white")
        plt.setp(ax1.get_yticklabels(), fontsize=8)

        ax2 = fig.add_subplot(2, 2, 2)
        user_counts = df["user"].value_counts().head(10)
        sns.barplot(
            x=user_counts.values,
            y=user_counts.index,
            hue=user_counts.index,
            palette=colors_users,
            legend=False,
            ax=ax2,
        )
        ax2.set_title("Топ-10 пользователей", fontsize=12, fontweight="bold", color="white")
        ax2.set_xlabel("Количество", color="white")
        ax2.set_ylabel("", color="white")
        ax2.set_facecolor("#2b2b2b")
        ax2.tick_params(colors="white")

        ax3 = fig.add_subplot(2, 2, 3)
        status_counts = df["status_ru"].value_counts()
        pie_colors = ["#4CAF50" if "Успешно" in s else "#F44336" for s in status_counts.index]
        wedges, texts, autotexts = ax3.pie(
            status_counts,
            labels=status_counts.index,
            autopct="%1.1f%%",
            colors=pie_colors,
            startangle=90,
        )
        for t in texts + autotexts:
            t.set_color("white")
        ax3.set_title("Успешные / Ошибки", fontsize=12, fontweight="bold", color="white")
        ax3.set_facecolor("#2b2b2b")

        ax4 = fig.add_subplot(2, 2, 4)
        valid_ts = df.dropna(subset=["timestamp"])
        if not valid_ts.empty:
            time_bins = valid_ts["timestamp"].dt.floor("h")
            time_counts = time_bins.value_counts().sort_index()
            ax4.plot(
                time_counts.index, time_counts.values,
                marker="o", markersize=4, color="#00BCD4", linewidth=2,
            )
            ax4.fill_between(time_counts.index, time_counts.values, alpha=0.2, color="#00BCD4")
            ax4.set_title("Активность по времени", fontsize=12, fontweight="bold", color="white")
            ax4.set_xlabel("Время", color="white")
            ax4.set_ylabel("Событий", color="white")
            for label in ax4.get_xticklabels():
                label.set_rotation(45)
                label.set_fontsize(7)
        else:
            ax4.text(0.5, 0.5, "Нет данных о времени", ha="center", va="center", color="white")
        ax4.set_facecolor("#2b2b2b")
        ax4.tick_params(colors="white")

        fig.tight_layout(pad=3.5, rect=[0, 0, 0.95, 1])

        canvas = FigureCanvasTkAgg(fig, master=parent_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

        toolbar = NavigationToolbar2Tk(canvas, parent_frame)
        toolbar.update()

        return fig

class Exporter:

    @staticmethod
    def to_csv(df, filepath):
        cols = ["timestamp", "user", "ip", "action_ru", "status_ru", "folder", "filepath"]
        existing_cols = [c for c in cols if c in df.columns]

        author = _get_author() if '_get_author' in globals() else "Nicolayka"
        with open(filepath, "w", encoding="utf-8-sig") as f:
            f.write(f"# Generated by Samba Audit Log Analyzer | Build: {author}\n")

        df[existing_cols].to_csv(filepath, mode="a", index=False, encoding="utf-8-sig")

    @staticmethod
    def to_html(df, stats, filepath, fig=None):
        cols = ["timestamp", "user", "ip", "action_ru", "status_ru", "folder", "filepath"]
        existing_cols = [c for c in cols if c in df.columns]
        table = df[existing_cols].head(500).to_html(index=False, classes="data-table")
        table = (
            table
            .replace("❌ Ошибка", '<span class="err">❌ Ошибка</span>')
            .replace("✅ Успешно", '<span class="ok">✅ Успешно</span>')
        )

        import io
        import base64
        chart_imgs = ""
        if fig is not None:
            try:
                buf = io.BytesIO()
                fig.savefig(buf, format='png', dpi=200, bbox_inches='tight',
                            facecolor=fig.get_facecolor(), edgecolor='none')
                buf.seek(0)
                encoded = base64.b64encode(buf.read()).decode('utf-8')
                chart_imgs = (
                    f'<img src="data:image/png;base64,{encoded}" '
                    f'style="max-width:100%; margin:10px 0; border-radius:8px; '
                    f'box-shadow:0 4px 6px rgba(0,0,0,0.3);">'
                )
                buf.close()
            except Exception as e:
                print(f"⚠️ Не удалось встроить график: {e}")

        author = _get_author() if '_get_author' in globals() else "Nicolayka"
        html = f"""<!DOCTYPE html>
    <!-- Build: {author} | Generated by Samba Audit Log Analyzer -->
    <html lang="ru"><head><meta charset="utf-8">
    <title>Samba Audit Report</title>
    <style>
      body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1e1e2e; color: #cdd6f4; margin: 40px; }}
      h1 {{ color: #89b4fa; }}
      h2 {{ color: #a6e3a1; }}
      .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
      .stat-card {{ background: #313244; padding: 20px; border-radius: 12px; text-align: center; }}
      .stat-card .num {{ font-size: 2em; font-weight: bold; color: #89b4fa; }}
      .stat-card .label {{ font-size: 0.9em; color: #a6adc8; }}
      .data-table {{ border-collapse: collapse; width: 100%; margin-top: 20px; font-size: 13px; }}
      .data-table th, .data-table td {{ border: 1px solid #45475a; padding: 8px 12px; text-align: left; }}
      .data-table th {{ background: #313244; position: sticky; top: 0; color: #cdd6f4; }}
      .data-table tr:nth-child(even) {{ background: #262637; }}
      .err {{ color: #f38ba8; font-weight: bold; }}
      .ok {{ color: #a6e3a1; }}
    </style></head><body>
    <h1> Отчёт по аудиту Samba</h1>
    <p>Сгенерировано: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}</p>

    <div class="stats">
      <div class="stat-card"><div class="num">{stats.get('total', 0)}</div><div class="label">Всего событий</div></div>
      <div class="stat-card"><div class="num">{stats.get('users', 0)}</div><div class="label">Пользователей</div></div>
      <div class="stat-card"><div class="num">{stats.get('folders', 0)}</div><div class="label">Папок / Ресурсов</div></div>
      <div class="stat-card"><div class="num">{stats.get('success', 0)}</div><div class="label">Успешных</div></div>
      <div class="stat-card"><div class="num">{stats.get('errors', 0)}</div><div class="label">Ошибок</div></div>
      <div class="stat-card"><div class="num">{stats.get('top_user', 'N/A')}</div><div class="label">Самый активный</div></div>
    </div>

    <h2>📊 Период: {stats.get('time_from', 'N/A')} — {stats.get('time_to', 'N/A')}</h2>

    {f'<h2>🖼️ Графики</h2><div>{chart_imgs}</div>' if chart_imgs else ''}

    <h2> Последние 500 событий</h2>
    {table}
    </body></html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

class SambaAnalyzerApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title(f"{APP_NAME} v{APP_VERSION}  ·  {_get_author()}")
        self.update_idletasks()
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - 1280) // 2
        y = (screen_height - 800) // 2
        self.geometry(f"1280x800+{x}+{y}")
        self.minsize(1000, 700)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.df = pd.DataFrame()
        self.current_file = None
        self.fig = None

        self._build_ui()

        self._flash_signature()

        self.bind_all("<Control-Shift-A>", lambda e: self._show_about())
        self.bind_all("<Control-Shift-a>", lambda e: self._show_about())

    def _build_ui(self):

        top_bar = ctk.CTkFrame(self, height=60, corner_radius=0)
        top_bar.pack(fill="x")
        top_bar.pack_propagate(False)

        self.btn_open = ctk.CTkButton(
            top_bar, text="📂 Открыть лог-файл", width=200, height=38,
            font=("Segoe UI", 13, "bold"),
            command=self._open_file,
        )
        self.btn_open.pack(side="left", padx=15, pady=10)

        self.lbl_file = ctk.CTkLabel(
            top_bar, text="Файл не выбран",
            font=("Segoe UI", 12), text_color="gray",
        )
        self.lbl_file.pack(side="left", padx=10)

        self.btn_html = ctk.CTkButton(
            top_bar, text="🌐 Экспорт HTML", width=150, height=34,
            fg_color="#45475a", hover_color="#585b70",
            command=self._export_html, state="disabled",
        )
        self.btn_html.pack(side="right", padx=8, pady=10)

        self.btn_csv = ctk.CTkButton(
            top_bar, text="📄 Экспорт CSV", width=150, height=34,
            fg_color="#45475a", hover_color="#585b70",
            command=self._export_csv, state="disabled",
        )
        self.btn_csv.pack(side="right", padx=8, pady=10)

        self.progress = ctk.CTkProgressBar(self, height=6, corner_radius=0)
        self.progress.pack(fill="x")
        self.progress.set(0)

        self.tabview = ctk.CTkTabview(self, segmented_button_fg_color="#313244")
        self.tabview.pack(fill="both", expand=True, padx=10, pady=(5, 10))

        self.tab_table = self.tabview.add("📋 Таблица событий")
        self.tab_charts = self.tabview.add("📈 Графики")
        self.tab_stats = self.tabview.add("📊 Статистика")

        self._build_table_tab()

        self.chart_container = ctk.CTkFrame(self.tab_charts, fg_color="transparent")
        self.chart_container.pack(fill="both", expand=True)

        self.chart_placeholder = ctk.CTkLabel(
            self.chart_container,
            text="📊 Загрузите лог-файл для построения графиков",
            font=("Segoe UI", 16), text_color="gray",
        )
        self.chart_placeholder.pack(expand=True)

        self.stats_frame = ctk.CTkScrollableFrame(self.tab_stats)
        self.stats_frame.pack(fill="both", expand=True)

        self.stats_placeholder = ctk.CTkLabel(
            self.stats_frame,
            text="📈 Статистика появится после загрузки файла",
            font=("Segoe UI", 16), text_color="gray",
        )
        self.stats_placeholder.pack(expand=True, pady=100)

        self.status_bar = ctk.CTkLabel(
            self, text="Готов к работе", height=28,
            font=("Segoe UI", 11), anchor="w",
            fg_color="#181825", corner_radius=0,
        )
        self.status_bar.pack(fill="x")

        self._setup_drag_drop()

    def _build_table_tab(self):
        search_frame = ctk.CTkFrame(self.tab_table, fg_color="transparent")
        search_frame.pack(fill="x", padx=5, pady=5)

        ctk.CTkLabel(search_frame, text="🔍 Поиск:").pack(side="left", padx=5)
        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._filter_table())
        search_entry = ctk.CTkEntry(search_frame, textvariable=self.search_var, width=400)
        search_entry.pack(side="left", padx=5)

        self.lbl_count = ctk.CTkLabel(search_frame, text="Записей: 0", font=("Segoe UI", 12))
        self.lbl_count.pack(side="right", padx=10)

        table_frame = ctk.CTkFrame(self.tab_table)
        table_frame.pack(fill="both", expand=True, padx=5, pady=5)

        columns = ("timestamp", "user", "ip", "action_ru", "status_ru", "folder", "filepath")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")

        headings = {
            "timestamp": ("Время", 160),
            "user": ("Пользователь", 110),
            "ip": ("IP-адрес", 120),
            "action_ru": ("Действие", 170),
            "status_ru": ("Статус", 90),
            "folder": ("Шара", 120),
            "filepath": ("Файл / Путь", 350),
        }

        for col, (title, width) in headings.items():
            self.tree.heading(col, text=title, command=lambda c=col: self._sort_table(c))
            self.tree.column(col, width=width, minwidth=80)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#2b2b2b", foreground="white",
            fieldbackground="#2b2b2b", font=("Segoe UI", 10),
            rowheight=28,
        )
        style.configure("Treeview.Heading", background="#313244", foreground="white", font=("Segoe UI", 10, "bold"))
        style.map("Treeview", background=[("selected", "#45475a")])

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

    def _setup_drag_drop(self):
        try:
            from tkinterdnd2 import DND_FILES
            self.drop_target_register(DND_FILES)
            self.dnd_bind("<<Drop>>", self._on_drop)
        except ImportError:
            pass

    def _open_file(self):
        filepath = filedialog.askopenfilename(
            title="Выберите лог-файл Samba",
            filetypes=[
                ("Log files", "*.log *.txt"),
                ("All files", "*.*"),
            ],
        )
        if filepath:
            self._load_file(filepath)

    def _on_drop(self, event):
        filepath = event.data.strip("{}")
        if os.path.isfile(filepath):
            self._load_file(filepath)

    def _load_file(self, filepath):
        self.current_file = filepath
        self.lbl_file.configure(
            text=f"📄 {os.path.basename(filepath)}",
            text_color="#a6e3a1",
        )
        self.status_bar.configure(text=f"⏳ Загрузка: {filepath} ...")
        self.update_idletasks()

        try:
            self.df, parsed, total = SambaParser.parse_file(
                filepath, progress_callback=self._update_progress
            )
        except Exception as e:
            messagebox.showerror("Ошибка чтения", f"Не удалось прочитать файл:\n{e}")
            self.status_bar.configure(text="❌ Ошибка чтения файла")
            return

        if self.df.empty:
            messagebox.showwarning(
                "Нет данных",
                "Не удалось извлечь ни одной записи.\n\n"
                "Убедитесь, что файл содержит строки 'smbd_audit:' в формате:\n"
                "timestamp host smbd_audit: user|ip|folder|action|status|filepath",
            )
            self.status_bar.configure(text="⚠️ Файл загружен, но данных не найдено")
            return

        self._populate_table(self.df)

        self._show_stats(SambaParser.get_stats(self.df))

        self.chart_placeholder.pack_forget()
        try:
            self.fig = ChartBuilder.build_all(self.df, self.chart_container, dpi=100)
        except Exception as e:
            self.status_bar.configure(text=f"⚠️ Ошибка построения графиков: {e}")

        self.btn_csv.configure(state="normal")
        self.btn_html.configure(state="normal")

        self.status_bar.configure(
            text=f"✅ Загружено {parsed} записей из {total} строк | {filepath}"
        )

    def _update_progress(self, fraction):
        self.progress.set(fraction)
        self.update_idletasks()

    def _populate_table(self, df):
        self.tree.delete(*self.tree.get_children())

        for _, row in df.iterrows():
            ts_val = row.get("timestamp", "")
            if pd.isna(ts_val) or ts_val == "":
                ts = "—"
            elif isinstance(ts_val, str):
                ts = ts_val
            else:
                try:
                    ts = ts_val.strftime("%Y-%m-%d %H:%M:%S")
                except:
                    ts = str(ts_val)

            self.tree.insert(
                "", "end",
                values=(
                    ts,
                    row.get("user", ""),
                    row.get("ip", ""),
                    row.get("action_ru", ""),
                    row.get("status_ru", ""),
                    row.get("folder", ""),
                    row.get("filepath", ""),
                ),
            )
        self.lbl_count.configure(text=f"Записей: {len(df)}")

    def _filter_table(self):
        query = self.search_var.get().lower().strip()
        if not query or self.df.empty:
            self._populate_table(self.df)
            return

        mask = (
            self.df.apply(lambda row: query in str(row.values).lower(), axis=1)
        )
        filtered = self.df[mask]
        self._populate_table(filtered)

    def _sort_table(self, col):
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        items.sort()
        for index, (_, k) in enumerate(items):
            self.tree.move(k, "", index)

    def _show_stats(self, stats):
        for widget in self.stats_frame.winfo_children():
            widget.destroy()

        if not stats:
            return

        section_title = ctk.CTkLabel(
            self.stats_frame,
            text="📊 ОБЩАЯ ИНФОРМАЦИЯ",
            font=("Segoe UI", 14, "bold"),
            text_color="#89b4fa",
        )
        section_title.pack(anchor="w", padx=20, pady=(20, 10))

        general_cards = [
            ("", "Всего событий", stats.get("total", 0), "#89b4fa"),
            ("✅", "Успешных операций", stats.get("success", 0), "#a6e3a1"),
            ("❌", "Ошибок", stats.get("errors", 0), "#f38ba8"),
            ("📈", "Процент успеха",
             f"{(stats.get('success', 0) / max(stats.get('total', 1), 1) * 100):.1f}%",
             "#f9e2af"),
        ]

        general_frame = ctk.CTkFrame(self.stats_frame, fg_color="transparent")
        general_frame.pack(fill="x", padx=20, pady=5)

        for i, (icon, label, value, color) in enumerate(general_cards):
            card = ctk.CTkFrame(general_frame, corner_radius=16, fg_color="#313244", border_width=2, border_color=color)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")

            icon_label = ctk.CTkLabel(
                card, text=icon,
                font=("Segoe UI", 28),
            )
            icon_label.pack(pady=(15, 5))

            val_label = ctk.CTkLabel(
                card, text=str(value),
                font=("Segoe UI", 26, "bold"),
                text_color=color,
            )
            val_label.pack(pady=(0, 5))

            lbl = ctk.CTkLabel(
                card, text=label,
                font=("Segoe UI", 11),
                text_color="#a6adc8",
                wraplength=150,
            )
            lbl.pack(padx=15, pady=(0, 15))

        for i in range(4):
            general_frame.grid_columnconfigure(i, weight=1)

        section_title2 = ctk.CTkLabel(
            self.stats_frame,
            text="👥 ПОЛЬЗОВАТЕЛИ И РЕСУРСЫ",
            font=("Segoe UI", 14, "bold"),
            text_color="#89b4fa",
        )
        section_title2.pack(anchor="w", padx=20, pady=(20, 10))

        user_cards = [
            ("", "Пользователей", stats.get("users", 0), "#cba6f7"),
            ("💻", "IP-адресов", stats.get("ips", 0), "#94e2d5"),
            ("📂", "Папок / Ресурсов", stats.get("folders", 0), "#fab387"),
            ("🏆", "Самый активный", stats.get("top_user", "N/A"), "#f5c2e7"),
        ]

        user_frame = ctk.CTkFrame(self.stats_frame, fg_color="transparent")
        user_frame.pack(fill="x", padx=20, pady=5)

        for i, (icon, label, value, color) in enumerate(user_cards):
            card = ctk.CTkFrame(user_frame, corner_radius=16, fg_color="#313244", border_width=2, border_color=color)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")

            icon_label = ctk.CTkLabel(card, text=icon, font=("Segoe UI", 28))
            icon_label.pack(pady=(15, 5))

            val_label = ctk.CTkLabel(
                card, text=str(value),
                font=("Segoe UI", 26, "bold"),
                text_color=color,
            )
            val_label.pack(pady=(0, 5))

            lbl = ctk.CTkLabel(
                card, text=label,
                font=("Segoe UI", 11),
                text_color="#a6adc8",
                wraplength=150,
            )
            lbl.pack(padx=15, pady=(0, 15))

        for i in range(4):
            user_frame.grid_columnconfigure(i, weight=1)

        section_title3 = ctk.CTkLabel(
            self.stats_frame,
            text="🕐 ВРЕМЕННОЙ ПЕРИОД",
            font=("Segoe UI", 14, "bold"),
            text_color="#89b4fa",
        )
        section_title3.pack(anchor="w", padx=20, pady=(20, 10))

        time_cards = [
            ("🟢", "Начало", stats.get("time_from", "N/A"), "#a6e3a1"),
            ("🔴", "Конец", stats.get("time_to", "N/A"), "#f38ba8"),
            ("⚡", "Частое действие", stats.get("top_action", "N/A"), "#f9e2af"),
        ]

        time_frame = ctk.CTkFrame(self.stats_frame, fg_color="transparent")
        time_frame.pack(fill="x", padx=20, pady=5)

        for i, (icon, label, value, color) in enumerate(time_cards):
            card = ctk.CTkFrame(time_frame, corner_radius=16, fg_color="#313244", border_width=2, border_color=color)
            card.grid(row=0, column=i, padx=10, pady=10, sticky="nsew")

            icon_label = ctk.CTkLabel(card, text=icon, font=("Segoe UI", 28))
            icon_label.pack(pady=(15, 5))

            val_label = ctk.CTkLabel(
                card, text=str(value),
                font=("Segoe UI", 20, "bold"),
                text_color=color,
                wraplength=250,
            )
            val_label.pack(pady=(0, 5))

            lbl = ctk.CTkLabel(
                card, text=label,
                font=("Segoe UI", 11),
                text_color="#a6adc8",
            )
            lbl.pack(padx=15, pady=(0, 15))

        for i in range(3):
            time_frame.grid_columnconfigure(i, weight=1)

    def _flash_signature(self):
        author = _get_author()
        original_text = self.status_bar.cget("text")
        self.status_bar.configure(text=f"🔧 Build verified by {author} | {original_text}")
        self.after(2500, lambda: self.status_bar.configure(text=original_text))

    def _show_about(self):
        author = _get_author()
        about_text = (
            f"╔══════════════════════════════════════╗\n"
            f"║  {APP_NAME} v{APP_VERSION}          ║\n"
            f"║                                      ║\n"
            f"║  Разработано: {author:<22}  ║\n"
            f"║  © 2026 Все права защищены          ║\n"
            f"║                                      ║\n"
            f"╚══════════════════════════════════════╝"
        )

        about_window = ctk.CTkToplevel(self)
        about_window.title("О программе")
        about_window.geometry("420x280")
        about_window.resizable(False, False)
        about_window.grab_set()

        about_window.update_idletasks()
        x = (self.winfo_screenwidth() - 420) // 2
        y = (self.winfo_screenheight() - 280) // 2
        about_window.geometry(f"420x280+{x}+{y}")

        frame = ctk.CTkFrame(about_window, fg_color="transparent")
        frame.pack(expand=True, fill="both", padx=20, pady=20)

        title = ctk.CTkLabel(
            frame, text=f"🛡️ {APP_NAME}",
            font=("Segoe UI", 20, "bold"),
            text_color="#89b4fa",
        )
        title.pack(pady=(10, 5))

        version = ctk.CTkLabel(
            frame, text=f"Версия {APP_VERSION}",
            font=("Segoe UI", 12),
            text_color="#a6adc8",
        )
        version.pack(pady=(0, 15))

        author_label = ctk.CTkLabel(
            frame, text=f"Разработчик: {author}",
            font=("Segoe UI", 14, "bold"),
            text_color="#a6e3a1",
        )
        author_label.pack(pady=5)

        copyright_lbl = ctk.CTkLabel(
            frame, text="© 2026 Все права защищены",
            font=("Segoe UI", 11),
            text_color="#6c7086",
        )
        copyright_lbl.pack(pady=5)

        hint = ctk.CTkLabel(
            frame, text="(Нажмите Ctrl+Shift+A в любом месте программы)",
            font=("Segoe UI", 9),
            text_color="#45475a",
        )
        hint.pack(pady=(15, 5))

        close_btn = ctk.CTkButton(
            frame, text="Закрыть", width=120,
            command=about_window.destroy,
        )
        close_btn.pack(pady=10)

        if not self.df.empty:
            section_title4 = ctk.CTkLabel(
                self.stats_frame,
                text="📋 ТОП-20 ДЕЙСТВИЙ ПО ПОЛЬЗОВАТЕЛЯМ",
                font=("Segoe UI", 14, "bold"),
                text_color="#89b4fa",
            )
            section_title4.pack(anchor="w", padx=20, pady=(30, 10))

            pivot = (
                self.df.groupby(["user", "action_ru"])
                .size()
                .reset_index(name="count")
                .sort_values("count", ascending=False)
                .head(20)
            )

            pivot_frame = ctk.CTkFrame(self.stats_frame, corner_radius=12)
            pivot_frame.pack(fill="x", padx=20, pady=10)

            header_frame = ctk.CTkFrame(pivot_frame, fg_color="#45475a", corner_radius=12)
            header_frame.pack(fill="x", padx=5, pady=5)

            headers = [("Пользователь", 200), ("Действие", 250), ("Количество", 100)]
            for col_idx, (col_name, width) in enumerate(headers):
                lbl = ctk.CTkLabel(
                    header_frame, text=col_name,
                    font=("Segoe UI", 12, "bold"),
                    text_color="white",
                    width=width,
                    anchor="w",
                )
                lbl.grid(row=0, column=col_idx, padx=10, pady=8, sticky="w")

            for row_idx, (_, row) in enumerate(pivot.iterrows(), 1):
                row_color = "#313244" if row_idx % 2 == 1 else "#2a2a3a"
                row_frame = ctk.CTkFrame(pivot_frame, fg_color=row_color, corner_radius=8)
                row_frame.pack(fill="x", padx=5, pady=2)

                values = [
                    (row["user"], 200, "#cdd6f4"),
                    (row["action_ru"], 250, "#a6adc8"),
                    (str(row["count"]), 100, "#89b4fa"),
                ]

                for col_idx, (val, width, color) in enumerate(values):
                    lbl = ctk.CTkLabel(
                        row_frame, text=str(val),
                        font=("Segoe UI", 11),
                        text_color=color,
                        width=width,
                        anchor="w",
                    )
                    lbl.grid(row=0, column=col_idx, padx=10, pady=6, sticky="w")

    def _export_csv(self):
        if self.df.empty:
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile="samba_audit_export.csv",
        )
        if filepath:
            try:
                Exporter.to_csv(self.df, filepath)
                self.status_bar.configure(text=f"✅ CSV сохранён: {filepath}")
                messagebox.showinfo("Готово", f"CSV-файл сохранён:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

    def _export_html(self):
        if self.df.empty:
            return
        filepath = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML", "*.html")],
            initialfile="samba_audit_report.html",
        )
        if filepath:
            try:
                stats = SambaParser.get_stats(self.df)
                Exporter.to_html(self.df, stats, filepath, fig=self.fig)
                self.status_bar.configure(text=f"✅ HTML-отчёт сохранён: {filepath}")
                if messagebox.askyesno("Готово", f"HTML-отчёт сохранён:\n{filepath}\n\nОткрыть в браузере?"):
                    webbrowser.open(filepath)
            except Exception as e:
                messagebox.showerror("Ошибка", str(e))

if __name__ == "__main__":
    app = SambaAnalyzerApp()
    app.mainloop()
