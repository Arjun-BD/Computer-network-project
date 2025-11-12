import os
import shlex
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

DEFAULT_BINARY = './out/blitzping'

class BlitzpingGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Blitzping GUI')
        self.geometry('900x600')

        self.proc = None
        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=8)
        frm.pack(fill='both', expand=True)

        top = ttk.Frame(frm)
        top.pack(fill='x')

        # Binary selection
        ttk.Label(top, text='blitzping binary:').grid(row=0, column=0, sticky='w')
        self.bin_var = tk.StringVar(value=DEFAULT_BINARY)
        bin_entry = ttk.Entry(top, textvariable=self.bin_var, width=60)
        bin_entry.grid(row=0, column=1, sticky='w')
        ttk.Button(top, text='Browse', command=self._browse_binary).grid(row=0, column=2, padx=6)

        # Run as sudo toggle
        self.sudo_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text='Run with sudo (or run GUI with sudo)', variable=self.sudo_var).grid(row=0, column=3, padx=6)

        # Dest and threads
        ttk.Label(top, text='Destination IP:').grid(row=1, column=0, sticky='w', pady=(8,0))
        self.dest_var = tk.StringVar(value='8.8.8.8')
        ttk.Entry(top, textvariable=self.dest_var, width=20).grid(row=1, column=1, sticky='w', pady=(8,0))

        ttk.Label(top, text='Num threads:').grid(row=1, column=2, sticky='w', pady=(8,0))
        self.threads_var = tk.StringVar(value='1')
        ttk.Entry(top, textvariable=self.threads_var, width=8).grid(row=1, column=3, sticky='w', pady=(8,0))

        # Traceroute
        self.tracert_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text='Traceroute (--tracert)', variable=self.tracert_var).grid(row=1, column=4, padx=6)

        # DPDK options
        dpdk_frame = ttk.Labelframe(frm, text='DPDK options', padding=8)
        dpdk_frame.pack(fill='x', pady=(10,0))

        self.use_dpdk_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(dpdk_frame, text='Use DPDK (--use-dpdk)', variable=self.use_dpdk_var).grid(row=0, column=0, sticky='w')

        ttk.Label(dpdk_frame, text='-l (core list):').grid(row=0, column=1, sticky='w', padx=(12,0))
        self.corelist_var = tk.StringVar(value='0')
        ttk.Entry(dpdk_frame, textvariable=self.corelist_var, width=10).grid(row=0, column=2, sticky='w')

        ttk.Label(dpdk_frame, text='-a (PCI address):').grid(row=0, column=3, sticky='w', padx=(12,0))
        self.pci_var = tk.StringVar(value='0000:38:00.0')
        ttk.Entry(dpdk_frame, textvariable=self.pci_var, width=18).grid(row=0, column=4, sticky='w')

        ttk.Label(dpdk_frame, text='Extra DPDK args:').grid(row=1, column=0, sticky='w', pady=(8,0))
        self.extra_dpdk_var = tk.StringVar(value='')
        ttk.Entry(dpdk_frame, textvariable=self.extra_dpdk_var, width=60).grid(row=1, column=1, columnspan=4, sticky='w', pady=(8,0))

        # Extra args
        args_frame = ttk.Frame(frm)
        args_frame.pack(fill='x', pady=(10,0))
        ttk.Label(args_frame, text='Additional blitzping args:').grid(row=0, column=0, sticky='w')
        self.extra_args_var = tk.StringVar(value='')
        ttk.Entry(args_frame, textvariable=self.extra_args_var, width=90).grid(row=1, column=0, sticky='w')

        # Buttons
        btns = ttk.Frame(frm)
        btns.pack(fill='x', pady=(12,0))
        self.start_btn = ttk.Button(btns, text='Start', command=self.start)
        self.start_btn.pack(side='left')
        self.stop_btn = ttk.Button(btns, text='Stop', command=self.stop, state='disabled')
        self.stop_btn.pack(side='left', padx=(8,0))
        ttk.Button(btns, text='Clear Output', command=self._clear_output).pack(side='right')

        # Output
        out_frame = ttk.Frame(frm)
        out_frame.pack(fill='both', expand=True, pady=(10,0))
        ttk.Label(out_frame, text='Output:').pack(anchor='w')
        self.text = tk.Text(out_frame, wrap='none')
        self.text.pack(fill='both', expand=True)

        # Scrollbars
        ysb = ttk.Scrollbar(self.text, orient='vertical', command=self.text.yview)
        self.text['yscrollcommand'] = ysb.set
        ysb.pack(side='right', fill='y')

    def _browse_binary(self):
        p = filedialog.askopenfilename(title='Select blitzping binary', initialfile=self.bin_var.get())
        if p:
            self.bin_var.set(p)

    def _build_command(self):
        bin_path = self.bin_var.get().strip()
        if not bin_path:
            raise ValueError('blitzping binary path is empty')
        if not os.path.isfile(bin_path):
            raise ValueError(f'Binary not found: {bin_path}')

        # We'll construct the command differently depending on whether DPDK/EAL args are needed.
        cmd = []
        if self.sudo_var.get():
            cmd.append('sudo')
        cmd.append(bin_path)

        dest = self.dest_var.get().strip()
        threads = self.threads_var.get().strip()

        # If using DPDK, EAL options (-l, -a, and other EAL flags) must appear BEFORE app args.
        if self.use_dpdk_var.get():
            # Add EAL options
            l = self.corelist_var.get().strip()
            a = self.pci_var.get().strip()
            if l:
                cmd.extend(['-l', l])
            if a:
                cmd.extend(['-a', a])

            extra_dpdk = shlex.split(self.extra_dpdk_var.get() or '')
            if extra_dpdk:
                cmd.extend(extra_dpdk)

            # Now add the '--' separator and application arguments (app sees these)
            cmd.append('--')

            # Ensure application-level --use-dpdk exists so blitzping knows to enable dpdk mode
            cmd.append('--use-dpdk')

            if dest:
                cmd.append(f'--dest-ip={dest}')
            if threads:
                cmd.append(f'--num-threads={threads}')

        else:
            # Non-DPDK flow: pass application args directly
            if dest:
                cmd.append(f'--dest-ip={dest}')
            if threads:
                cmd.append(f'--num-threads={threads}')

        # Traceroute
        if self.tracert_var.get():
            cmd.append('--tracert')

        # Additional args the user typed
        extra = shlex.split(self.extra_args_var.get() or '')
        if extra:
            cmd.extend(extra)

        return cmd

    def start(self):
        try:
            cmd = self._build_command()
        except Exception as e:
            messagebox.showerror('Invalid command', str(e))
            return

        if self.proc is not None:
            messagebox.showwarning('Already running', 'A blitzping process is already running')
            return

        self._append_output(f'Running: {shlex.join(cmd)}\n\n')

        try:
            # Start process
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        except Exception as e:
            self._append_output(f'Failed to start process: {e}\n')
            self.proc = None
            return

        # UI state
        self.start_btn['state'] = 'disabled'
        self.stop_btn['state'] = 'normal'

        # Thread to read output
        t = threading.Thread(target=self._read_process_output, daemon=True)
        t.start()

    def _read_process_output(self):
        try:
            for line in self.proc.stdout:
                self._append_output(line)
        except Exception as e:
            self._append_output(f'Error reading process output: {e}\n')
        finally:
            rc = self.proc.wait()
            self._append_output(f'\nProcess exited with return code {rc}\n')
            self.proc = None
            self.start_btn['state'] = 'normal'
            self.stop_btn['state'] = 'disabled'

    def stop(self):
        if not self.proc:
            return
        try:
            self._append_output('\nTerminating process...\n')
            self.proc.terminate()
            # Give it a short time, then kill
            threading.Timer(2.0, self._kill_if_needed).start()
        except Exception as e:
            self._append_output(f'Failed to terminate process: {e}\n')

    def _kill_if_needed(self):
        if self.proc:
            try:
                self._append_output('Killing process...\n')
                self.proc.kill()
            except Exception as e:
                self._append_output(f'Failed to kill process: {e}\n')

    def _append_output(self, s):
        # Insert into text widget from main thread
        def _insert():
            self.text.insert('end', s)
            self.text.see('end')
        self.after(0, _insert)

    def _clear_output(self):
        self.text.delete('1.0', 'end')


if __name__ == '__main__':
    app = BlitzpingGUI()
    app.mainloop()
