"""User-owned desktop panel. All printing runs through the local queue."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
import sys

from .local_queue import LocalQueue
from .plugins import REGISTRY, discover_printers
from .cloud_accounts import CloudAccountSettings
from .desktop_settings import DesktopSettings
from .desktop_cloud import CloudDesktopController
import os


class DesktopController:
    """A small interface for the GUI, kept usable without a display server."""

    def __init__(self, state_dir=None, backend='auto', windows_renderer=None, auth_dir=None):
        self.queue = LocalQueue(state_dir, backend, windows_renderer)
        self.backend = backend
        self.accounts = CloudAccountSettings(auth_dir)
        self.settings = DesktopSettings(self.queue.root)
        self.cloud = CloudDesktopController(self.accounts, self.queue.root / 'cloud-gateways')
        if os.name == 'nt' and not windows_renderer:
            self.queue.windows_renderer = self.settings.renderer()

    def set_windows_renderer(self, executable):
        path = self.settings.set_renderer(executable)
        self.queue.windows_renderer = path
        return path

    def printers(self):
        return discover_printers(self.backend)

    def jobs(self):
        return self.queue.jobs(250)

    def submit(self, pdf, printer, held=True):
        return self.queue.submit(Path(pdf), printer, held=held)

    def hold(self, job):
        return self.queue.hold(job)

    def release(self, job):
        return self.queue.release(job)

    def cancel(self, job):
        return self.queue.cancel(job)

    def process(self, job):
        return self.queue.process_one(job)

    def history(self, job):
        return self.queue.history(job)

    def interrupted(self, job):
        return self.queue.mark_interrupted(job)

    @staticmethod
    def plugins():
        return REGISTRY.list()


def _time_label(timestamp):
    try:
        return datetime.fromtimestamp(int(timestamp)).strftime('%d %b %Y %H:%M')
    except (ValueError, OverflowError, TypeError, OSError):
        return 'Unknown'


class DesktopPanel:
    def __init__(self, root, controller=None):
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk = tk, ttk
        self.root = root
        self.ctrl = controller or DesktopController()
        self.messages = Queue()
        self.pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix='tabarc-print')
        self.closed = False
        self.busy = False
        self.printer = tk.StringVar()
        self.hold_new = tk.BooleanVar(value=True)
        self.status = tk.StringVar(value='Local printing. Nothing is sent to TABARC-Code.')
        self.accounts_window = None
        self.cloud_window = None

        root.title('TABARC Print | Local printers')
        root.geometry('930x620')
        root.minsize(680, 450)
        frame = ttk.Frame(root, padding=14)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='TABARC Print', font=('TkDefaultFont', 16, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Your documents stay on this computer unless you explicitly use a cloud gateway.').pack(anchor='w', pady=(0, 14))

        bar = ttk.Frame(frame)
        bar.pack(fill='x', pady=(0, 9))
        ttk.Label(bar, text='Local printer:').pack(side='left')
        self.printer_widget = ttk.Combobox(bar, textvariable=self.printer, width=37)
        self.printer_widget.pack(side='left', padx=7)
        self.find_button = ttk.Button(bar, text='Find printers', command=self.refresh_printers)
        self.find_button.pack(side='left')
        ttk.Checkbutton(bar, text='Hold new jobs', variable=self.hold_new).pack(side='left', padx=(14, 0))

        controls = ttk.Frame(frame)
        controls.pack(fill='x', pady=(0, 9))
        self.actions = {}
        for n, (label, command) in enumerate([('Add PDF', self.choose_document), ('Hold', self.hold_selected),
                               ('Release', self.release_selected), ('Print selected', self.print_selected),
                               ('Cancel', self.cancel_selected), ('Mark uncertain', self.mark_uncertain),
                               ('History', self.show_history),
                               ('Plug-ins', self.show_plugins), ('Cloud accounts', self.show_accounts),
                               ('Cloud printing', self.show_cloud_print),
                               ('Settings', self.show_settings), ('Refresh', self.refresh_jobs)]):
            b = ttk.Button(controls, text=label, command=command)
            b.grid(row=n // 5, column=n % 5, padx=(0, 5), pady=2, sticky='ew')
            self.actions[label] = b
        for col in range(5):
            controls.columnconfigure(col, weight=1)

        columns = ('file', 'printer', 'state', 'created', 'spool')
        table_frame = ttk.Frame(frame)
        table_frame.pack(fill='both', expand=True)
        self.table = ttk.Treeview(table_frame, columns=columns, show='headings', selectmode='browse')
        widths = {'file': 190, 'printer': 145, 'state': 90, 'created': 140, 'spool': 160}
        for key, label in [('file', 'Document'), ('printer', 'Printer'), ('state', 'State'),
                           ('created', 'Added'), ('spool', 'Spool reference')]:
            self.table.heading(key, text=label)
            self.table.column(key, width=widths[key], minwidth=70, stretch=True)
        scrollbar = ttk.Scrollbar(table_frame, orient='vertical', command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        self.table.bind('<<TreeviewSelect>>', lambda _e: self._update_actions())

        ttk.Label(frame, textvariable=self.status, wraplength=850).pack(anchor='w', pady=(10, 0))
        ttk.Label(frame, text='Submitted = accepted by the operating system, not confirmation of a printed page.',
                  wraplength=850).pack(anchor='w', pady=(5, 0))
        root.protocol('WM_DELETE_WINDOW', self.close)
        self.refresh_jobs()
        self.refresh_printers()
        root.after(120, self._poll)
        root.after(5000, self._refresh_periodic)

    def _selected(self):
        selection = self.table.selection()
        return selection[0] if selection else None

    def _selected_state(self):
        jid = self._selected()
        if not jid:
            return None
        return self.table.set(jid, 'state')

    def _update_actions(self):
        state = self._selected_state()
        for action, allowed in [('Hold', state == 'queued'), ('Release', state == 'held'),
                                ('Print selected', state == 'queued'),
                                ('Cancel', state in ('held', 'queued')), ('Mark uncertain', state == 'claimed'),
                                ('History', state is not None)]:
            self.actions[action].configure(state=('normal' if allowed and not self.busy else 'disabled'))
        self.actions['Add PDF'].configure(state=('disabled' if self.busy else 'normal'))
        self.find_button.configure(state=('disabled' if self.busy else 'normal'))
        self.actions['Cloud accounts'].configure(state=('disabled' if self.busy else 'normal'))
        self.actions['Cloud printing'].configure(state=('disabled' if self.busy else 'normal'))
        self.actions['Settings'].configure(state=('disabled' if self.busy else 'normal'))

    def _run(self, label, fn, on_success=None):
        if self.busy:
            return
        self.busy = True
        self.status.set(label + '…')
        self._update_actions()
        future = self.pool.submit(fn)
        future.add_done_callback(lambda f: self.messages.put((label, f, on_success)))

    def _poll(self):
        if self.closed:
            return
        from tkinter import messagebox
        try:
            while True:
                label, future, done = self.messages.get_nowait()
                if label == 'device-prompt':
                    self._show_device_prompt(future)
                    continue
                self.busy = False
                try:
                    result = future.result()
                    if done:
                        done(result)
                    else:
                        self.status.set(label + ' finished')
                except Exception as exc:
                    self.status.set(label + ' failed: ' + str(exc)[:130])
                    if label != 'Finding printers':
                        messagebox.showerror('TABARC Print', f'{label}: {exc}')
                self._update_actions()
        except Empty:
            pass
        self.root.after(120, self._poll)

    def _refresh_periodic(self):
        if self.closed:
            return
        if not self.busy:
            try:
                self.refresh_jobs()
            except Exception as exc:
                self.status.set('Could not refresh local queue: ' + str(exc)[:130])
        self.root.after(5000, self._refresh_periodic)

    def refresh_printers(self):
        def loaded(names):
            self.printer_widget['values'] = names
            if not self.printer.get() and names:
                self.printer.set(names[0])
            self.status.set(f'{len(names)} local printer(s) found. You can also enter a queue name.')
        self._run('Finding printers', self.ctrl.printers, loaded)

    def refresh_jobs(self):
        current = self._selected()
        for child in self.table.get_children():
            self.table.delete(child)
        for j in self.ctrl.jobs():
            self.table.insert('', 'end', iid=j['id'], values=(
                j['filename'], j['printer'], j['state'], _time_label(j['created_at']), j.get('spool_ref') or ''))
        if current and self.table.exists(current):
            self.table.selection_set(current)
        self._update_actions()

    def choose_document(self):
        from tkinter import filedialog, messagebox
        printer = self.printer.get().strip()
        if not printer:
            messagebox.showwarning('TABARC Print', 'Choose or enter a local printer first.')
            return
        path = filedialog.askopenfilename(title='Choose PDF', filetypes=[('PDF documents', '*.pdf')])
        if not path:
            return
        held = self.hold_new.get()
        self._run('Adding PDF', lambda: self.ctrl.submit(path, printer, held), self._submitted)

    def _submitted(self, jid):
        self.refresh_jobs()
        self.table.selection_set(jid)
        self.table.see(jid)
        self.status.set(f'Job {jid[:12]} added locally. Select Release and then Print selected to submit it.')

    def _selected_job_action(self, verb, fn, next_text):
        jid = self._selected()
        if not jid:
            return
        def applied(result):
            self.refresh_jobs()
            if isinstance(result, bool) and not result:
                self.status.set('The job changed state; refresh and inspect it before continuing.')
            else:
                self.status.set(next_text if not isinstance(result, tuple) else
                                f'Job {result[0][:12]}: {result[1]}. {str(result[2])[:180]}')
        self._run(verb, lambda: fn(jid), applied)

    def hold_selected(self):
        self._selected_job_action('Holding job', self.ctrl.hold, 'Job held')

    def release_selected(self):
        self._selected_job_action('Releasing job', self.ctrl.release, 'Job released to queue')

    def cancel_selected(self):
        from tkinter import messagebox
        if self._selected() and messagebox.askyesno('Cancel print job', 'Cancel the selected job before spooler submission?'):
            self._selected_job_action('Cancelling job', self.ctrl.cancel, 'Job cancelled')

    def mark_uncertain(self):
        from tkinter import messagebox
        if self._selected() and messagebox.askyesno('Interrupted submission',
            'Only proceed after stopping every background print worker. Mark this claimed job as uncertain? This does not reprint it.'):
            self._selected_job_action('Marking interrupted job', self.ctrl.interrupted,
                                      'Job marked uncertain. Inspect the printer before deciding what to do next.')

    def print_selected(self):
        from tkinter import messagebox
        if self._selected() and messagebox.askyesno('Submit to printer',
                'Submit this document to the selected operating-system printer? This may print paper.'):
            self._selected_job_action('Submitting to printer', self.ctrl.process,
                                      'Job submitted to the operating system')

    def show_history(self):
        jid = self._selected()
        if not jid:
            return
        window = self.tk.Toplevel(self.root)
        window.title('Job history | ' + jid[:12])
        window.geometry('600x330')
        text = self.tk.Text(window, wrap='word', state='normal')
        text.pack(fill='both', expand=True)
        for event in reversed(self.ctrl.history(jid)):
            text.insert('end', f"{_time_label(event['at'])}    {event['state']}\n")
            if event['detail']:
                text.insert('end', event['detail'] + '\n')
        text.configure(state='disabled')

    def show_plugins(self):
        window = self.tk.Toplevel(self.root)
        window.title('Approved built-in plug-ins')
        window.geometry('590x320')
        text = self.tk.Text(window, wrap='word')
        text.pack(fill='both', expand=True)
        for item in self.ctrl.plugins():
            text.insert('end', f"{item.name} [{item.kind}]\n{item.description}\n"
                f"Permissions: {', '.join(item.permissions)}\n\n")
        text.insert('end', 'Third-party executable plug-ins are not loaded automatically.')
        text.configure(state='disabled')

    def show_settings(self):
        from tkinter import filedialog, messagebox
        if os.name != 'nt':
            messagebox.showinfo('TABARC Print settings',
                                'Linux printing uses the configured CUPS queue.', parent=self.root)
            return
        current = self.ctrl.queue.windows_renderer or 'Not configured'
        if not messagebox.askyesno('Windows PDF renderer',
                f'Current renderer: {current}\n\nChoose your trusted, locally installed SumatraPDF.exe?',
                parent=self.root):
            return
        path = filedialog.askopenfilename(parent=self.root, title='Choose SumatraPDF.exe',
                                          filetypes=[('Windows applications', '*.exe')])
        if not path:
            return
        try:
            self.ctrl.set_windows_renderer(path)
            self.status.set('Saved local PDF renderer. No print job was submitted.')
        except Exception as exc:
            messagebox.showerror('TABARC Print settings', str(exc), parent=self.root)

    def _show_device_prompt(self, info):
        # This callback runs on the GUI thread. The device-code login stays on the worker.
        from tkinter import messagebox
        messagebox.showinfo('Microsoft account sign-in',
            f"Open {info['url']} in a browser and enter code: {info['code']}\n\n" +
            "TABARC Print is waiting for Microsoft to confirm your sign-in.")

    def show_accounts(self):
        from tkinter import messagebox, ttk
        if self.accounts_window is not None and self.accounts_window.winfo_exists():
            self.accounts_window.lift()
            return
        window = self.tk.Toplevel(self.root)
        self.accounts_window = window
        window.title('Cloud accounts | TABARC Print')
        window.geometry('690x400')
        window.minsize(540, 340)
        frame = ttk.Frame(window, padding=15)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Optional cloud gateways', font=('TkDefaultFont', 13, 'bold')).grid(
            row=0, column=0, columnspan=3, sticky='w', pady=(0, 5))
        ttk.Label(frame, text='Local printing works without signing in. Account tokens stay on this computer.',
                  wraplength=600).grid(row=1, column=0, columnspan=3, sticky='w', pady=(0, 15))
        try:
            initial = self.ctrl.accounts.load()
        except Exception as exc:
            messagebox.showerror('Account settings', str(exc), parent=window)
            window.destroy()
            return
        google = self.tk.StringVar(value=initial['google_credentials'])
        client = self.tk.StringVar(value=initial['microsoft_client_id'])
        tenant = self.tk.StringVar(value=initial['microsoft_tenant'])
        gstatus, mstatus = self.tk.StringVar(), self.tk.StringVar()
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text='Google client JSON').grid(row=2, column=0, sticky='w')
        ttk.Entry(frame, textvariable=google).grid(row=2, column=1, sticky='ew', padx=8, pady=4)
        def browse_google():
            from tkinter import filedialog
            path = filedialog.askopenfilename(parent=window, title='Google desktop OAuth client JSON',
                filetypes=[('JSON file', '*.json')])
            if path:
                google.set(path)
        ttk.Button(frame, text='Browse', command=browse_google).grid(row=2, column=2)
        ttk.Label(frame, text='Microsoft app ID').grid(row=3, column=0, sticky='w')
        ttk.Entry(frame, textvariable=client).grid(row=3, column=1, sticky='ew', padx=8, pady=4)
        ttk.Label(frame, text='Microsoft tenant').grid(row=4, column=0, sticky='w')
        ttk.Combobox(frame, textvariable=tenant, values=('consumers', 'organizations', 'common')).grid(
            row=4, column=1, sticky='ew', padx=8, pady=4)
        ttk.Label(frame, textvariable=gstatus).grid(row=5, column=1, sticky='w')
        ttk.Label(frame, textvariable=mstatus).grid(row=6, column=1, sticky='w')
        actions = ttk.Frame(frame)
        actions.grid(row=7, column=0, columnspan=3, sticky='w', pady=(12, 0))
        def refresh():
            try:
                gstatus.set('Google: ' + self.ctrl.accounts.status('google')['message'])
                mstatus.set('Microsoft: ' + self.ctrl.accounts.status('onedrive')['message'])
            except Exception as exc:
                messagebox.showerror('Cloud accounts', str(exc), parent=window)
        def save():
            try:
                self.ctrl.accounts.save(google.get(), client.get(), tenant.get())
            except Exception as exc:
                messagebox.showerror('Cloud accounts', str(exc), parent=window)
                return
            refresh()
            self.status.set('Cloud app settings saved locally. No document was uploaded.')
        def login(provider):
            if self.busy:
                return
            def done(_result):
                if window.winfo_exists():
                    refresh()
                self.status.set('Cloud sign-in finished. Live print transport is not yet verified.')
            self._run('Signing in to ' + provider,
                lambda: self.ctrl.accounts.sign_in(provider,
                    notify=lambda info: self.messages.put(('device-prompt', info, None))), done)
        def disconnect(provider):
            if self.busy:
                return
            if messagebox.askyesno('Remove local token',
                'Remove the saved local token? This does not revoke access at the provider.', parent=window):
                try:
                    self.ctrl.accounts.forget_local_token(provider)
                    refresh()
                except Exception as exc:
                    messagebox.showerror('Cloud accounts', str(exc), parent=window)
        ttk.Button(actions, text='Save settings', command=save).pack(side='left', padx=(0, 6))
        ttk.Button(actions, text='Sign in Google', command=lambda: login('google')).pack(side='left', padx=(0, 6))
        ttk.Button(actions, text='Sign in OneDrive', command=lambda: login('onedrive')).pack(side='left')
        extras = ttk.Frame(frame)
        extras.grid(row=8, column=0, columnspan=3, sticky='w', pady=(8, 0))
        ttk.Button(extras, text='Clear Google token', command=lambda: disconnect('google')).pack(side='left', padx=(0, 6))
        ttk.Button(extras, text='Clear OneDrive token', command=lambda: disconnect('onedrive')).pack(side='left')
        ttk.Label(frame, text='Cloud printing is optional. The separate Cloud printing panel handles send and collect operations.',
                  wraplength=600).grid(row=9, column=0, columnspan=3, sticky='w', pady=(15, 0))
        refresh()

    def show_cloud_print(self):
        from tkinter import filedialog, messagebox, ttk
        if self.cloud_window is not None and self.cloud_window.winfo_exists():
            self.cloud_window.lift()
            return
        window = self.tk.Toplevel(self.root)
        self.cloud_window = window
        window.title('Cloud printing | TABARC Print')
        window.geometry('780x625')
        window.minsize(670, 555)
        frame = ttk.Frame(window, padding=14)
        frame.pack(fill='both', expand=True)
        frame.columnconfigure(1, weight=1)
        ttk.Label(frame, text='Send or collect encrypted print jobs',
                  font=('TkDefaultFont', 13, 'bold')).grid(row=0, column=0, columnspan=3, sticky='w')
        ttk.Label(frame, text='Sign in from Cloud accounts first. Use the same cloud mailbox and pairing key on both devices.',
                  wraplength=660).grid(row=1, column=0, columnspan=3, sticky='w', pady=(4, 14))
        provider = self.tk.StringVar(value='google')
        key = self.tk.StringVar()
        remote = self.tk.StringVar()
        local = self.tk.StringVar()
        enabled = self.tk.BooleanVar(value=False)
        target = self.tk.StringVar()
        document = self.tk.StringVar()
        job = self.tk.StringVar()
        state = self.tk.StringVar(value='No cloud operation has started.')
        ttk.Label(frame, text='Cloud provider').grid(row=2, column=0, sticky='w')
        provider_box = ttk.Combobox(frame, textvariable=provider, values=('google', 'onedrive'), state='readonly')
        provider_box.grid(row=2, column=1, sticky='ew', padx=8, pady=3)
        ttk.Label(frame, text='Pairing key').grid(row=3, column=0, sticky='w')
        key_entry = ttk.Entry(frame, textvariable=key, show='*')
        key_entry.grid(row=3, column=1, sticky='ew', padx=8, pady=3)
        def generate():
            if messagebox.askyesno('Replace pairing key',
                    'Replacing an existing key prevents the other device from reading new jobs until it is updated.',
                    parent=window):
                key.set(self.ctrl.cloud.profiles.generate_key())
                state.set('New key generated. Save this profile on both devices.')
        ttk.Button(frame, text='Generate', command=generate).grid(row=3, column=2)
        ttk.Label(frame, text='Remote printer ID').grid(row=4, column=0, sticky='w')
        ttk.Entry(frame, textvariable=remote).grid(row=4, column=1, sticky='ew', padx=8, pady=3)
        ttk.Label(frame, text='Local printer').grid(row=5, column=0, sticky='w')
        ttk.Entry(frame, textvariable=local).grid(row=5, column=1, sticky='ew', padx=8, pady=3)
        ttk.Label(frame, text='Target receiver ID').grid(row=6, column=0, sticky='w')
        ttk.Entry(frame, textvariable=target).grid(row=6, column=1, sticky='ew', padx=8, pady=3)
        ttk.Label(frame, text='Leave empty only for older, single-receiver mailboxes.',
                  wraplength=250).grid(row=6, column=2, sticky='w')
        ttk.Checkbutton(frame, text='Allow this computer to receive jobs for this printer ID',
                        variable=enabled).grid(row=7, column=0, columnspan=3, sticky='w', pady=5)
        def load_profile(*_):
            try:
                profile = self.ctrl.cloud.profiles.load(provider.get())
                key.set(profile['secret'])
                remote.set(profile['remote_id'])
                local.set(profile['local_printer'])
                enabled.set(profile['receive_enabled'])
                target.set(profile['receiver_id'])
            except Exception as exc:
                messagebox.showerror('Cloud profile', str(exc), parent=window)
        provider_box.bind('<<ComboboxSelected>>', load_profile)
        def save_profile():
            try:
                self.ctrl.cloud.profiles.save(provider.get(), secret=key.get(),
                     remote_id=remote.get().strip(), local_printer=local.get().strip(),
                     receive_enabled=enabled.get(), receiver_id=target.get().strip())
                state.set('Profile saved on this computer. No cloud job was sent or received.')
            except Exception as exc:
                messagebox.showerror('Cloud profile', str(exc), parent=window)
        row = ttk.Frame(frame)
        row.grid(row=8, column=0, columnspan=3, sticky='w', pady=(3, 10))
        ttk.Button(row, text='Save pairing', command=save_profile).pack(side='left', padx=(0, 8))
        def copy_receiver_id():
            try:
                value = self.ctrl.cloud.receiver_id()
                window.clipboard_clear()
                window.clipboard_append(value)
                state.set('This computer’s receiver ID copied. Paste it into the sender’s Target receiver ID field.')
            except Exception as exc:
                messagebox.showerror('Receiver identity', str(exc), parent=window)
        ttk.Button(row, text='Copy this computer’s receiver ID', command=copy_receiver_id).pack(side='left')
        ttk.Separator(frame).grid(row=9, column=0, columnspan=3, sticky='ew', pady=7)
        ttk.Label(frame, text='PDF to send').grid(row=10, column=0, sticky='w')
        ttk.Entry(frame, textvariable=document).grid(row=10, column=1, sticky='ew', padx=8, pady=3)
        ttk.Button(frame, text='Browse', command=lambda: document.set(
            filedialog.askopenfilename(parent=window, filetypes=[('PDF', '*.pdf')]) or document.get())
        ).grid(row=10, column=2)
        ttk.Label(frame, text='Job ID').grid(row=11, column=0, sticky='w')
        ttk.Entry(frame, textvariable=job).grid(row=11, column=1, sticky='ew', padx=8, pady=3)
        actions = ttk.Frame(frame)
        actions.grid(row=12, column=0, columnspan=3, sticky='w', pady=10)
        def send_job():
            saved = self.ctrl.cloud.profiles.load(provider.get())
            if saved['receiver_id'] != target.get().strip():
                messagebox.showwarning('Cloud print', 'Save the updated target receiver ID before sending.', parent=window)
                return
            if not remote.get().strip() or not document.get():
                messagebox.showwarning('Cloud print', 'Choose a PDF and remote printer ID.', parent=window)
                return
            if not target.get().strip() and not messagebox.askyesno(
                    'Unbound print job',
                    'This job is not bound to a specific receiver. Multiple receiving computers could both print it. Continue?',
                    parent=window):
                return
            if not messagebox.askyesno('Send encrypted document',
                    'Upload this encrypted PDF to the selected cloud account for the paired printer?', parent=window):
                return
            def done(ident):
                job.set(ident)
                state.set('Uploaded encrypted job ' + ident[:12] + '. Awaiting receiver.')
            chosen_provider, chosen_document, chosen_remote = provider.get(), document.get(), remote.get().strip()
            self._run('Sending cloud job', lambda: self.ctrl.cloud.send(chosen_provider, chosen_document, chosen_remote), done)
        def check_status():
            def done(result):
                state.set('Job awaiting collection or receipt.' if result is None else
                          'Receiver status: ' + str(result.get('state')) + '. ' + str(result.get('message', ''))[:160])
            chosen_provider, chosen_job = provider.get(), job.get().strip()
            self._run('Checking cloud receipt', lambda: self.ctrl.cloud.status(chosen_provider, chosen_job), done)
        def receive():
            if not messagebox.askyesno('Collect and print remote jobs',
                    'Fetch this account’s encrypted print jobs and submit matching jobs to the mapped local printer?'
                    ' This can produce paper. Print once only on a trusted receiving computer.', parent=window):
                return
            def done(result):
                state.set('Receive check: ' + (str(result)[:270] if result else 'No new jobs.'))
            chosen_provider = provider.get()
            self._run('Collecting cloud jobs', lambda: self.ctrl.cloud.receive_once(chosen_provider,
                backend=self.ctrl.backend, windows_renderer=self.ctrl.queue.windows_renderer), done)
        ttk.Button(actions, text='Send', command=send_job).pack(side='left', padx=(0, 7))
        ttk.Button(actions, text='Check status', command=check_status).pack(side='left', padx=(0, 7))
        ttk.Button(actions, text='Collect and print once', command=receive).pack(side='left')
        ttk.Label(frame, textvariable=state, wraplength=660).grid(row=13, column=0, columnspan=3, sticky='w', pady=(9, 3))
        ttk.Label(frame, text='Pairing keys require an operating-system credential vault. No plaintext key-file fallback.'
                  ' Copy the receiving computer’s ID to the sender. A submitted job is not proof of paper output.',
                  wraplength=660).grid(row=14, column=0, columnspan=3, sticky='w', pady=(5, 0))
        load_profile()

    def close(self):
        self.closed = True
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.root.destroy()


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description='TABARC Print desktop application')
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--auth-dir', type=Path, help='Private cloud token directory')
    parser.add_argument('--backend', choices=('auto', 'cups', 'windows-sumatra'), default='auto')
    parser.add_argument('--windows-renderer', help='Absolute path to the trusted PDF renderer on Windows')
    args = parser.parse_args(argv)
    try:
        import tkinter as tk
        root = tk.Tk()
    except Exception as exc:
        # Tcl errors are platform-specific; show a clear error and leave the CLI available.
        print('Desktop interface unavailable: ' + str(exc), file=sys.stderr)
        return 1
    try:
        DesktopPanel(root, DesktopController(args.state_dir, args.backend, args.windows_renderer, args.auth_dir))
    except Exception as exc:
        root.destroy()
        print('Cannot start TABARC Print: ' + str(exc), file=sys.stderr)
        return 1
    root.mainloop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
