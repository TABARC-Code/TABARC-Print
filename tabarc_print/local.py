"""Local-first command line. The cloud and browser integrations are optional."""
import argparse
import json
from pathlib import Path
import time

from .local_queue import LocalQueue
from .plugins import REGISTRY, discover_printers


def main(argv=None):
    parser = argparse.ArgumentParser(description='TABARC Print: your printers, your computer')
    parser.add_argument('--state-dir', type=Path, help='Private local job database and documents')
    parser.add_argument('--backend', choices=('auto', 'cups', 'windows-sumatra'), default='auto')
    parser.add_argument('--windows-renderer', help='Trusted absolute path to SumatraPDF.exe')
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('printers', help='List printers known to the operating system')
    plugins = sub.add_parser('plugins', help='Show approved built-in plug-ins')
    plugins.add_argument('--kind', choices=('printer', 'transport'))
    submit = sub.add_parser('submit', help='Queue a PDF locally')
    submit.add_argument('--pdf', type=Path, required=True)
    submit.add_argument('--printer', required=True, help='Local print queue name')
    submit.add_argument('--hold', action='store_true', help='Keep job private until explicitly released')
    submit.add_argument('--print-now', action='store_true', help='Submit immediately, rather than wait for a worker')
    submit.add_argument('--dry-run', action='store_true')
    jobs = sub.add_parser('jobs', help='Show local job history')
    jobs.add_argument('--limit', type=int, default=50)
    work = sub.add_parser('work', help='Process queued jobs; run as a user-owned background service')
    work.add_argument('--once', action='store_true')
    work.add_argument('--interval', type=float, default=3)
    work.add_argument('--dry-run', action='store_true')
    hold = sub.add_parser('hold', help='Hold a queued job')
    hold.add_argument('--job', required=True)
    release = sub.add_parser('release', help='Release a held job to the queue')
    release.add_argument('--job', required=True)
    history = sub.add_parser('history', help='Show the local job event history')
    history.add_argument('--job', required=True)
    cancel = sub.add_parser('cancel', help='Cancel a job that has not been claimed')
    cancel.add_argument('--job', required=True)
    interrupted = sub.add_parser('interrupted', help='Mark a stranded claim as uncertain after stopping the previous worker')
    interrupted.add_argument('--job', required=True)
    args = parser.parse_args(argv)

    if args.action == 'plugins':
        print(json.dumps([{'name': p.name, 'kind': p.kind, 'description': p.description,
                           'permissions': list(p.permissions), 'optional': p.optional}
                           for p in REGISTRY.list(args.kind)], indent=2))
        return 0
    if args.action == 'printers':
        print(json.dumps(discover_printers(args.backend), indent=2))
        return 0

    queue = LocalQueue(args.state_dir, args.backend, args.windows_renderer)
    if args.action == 'submit':
        if args.hold and args.print_now:
            parser.error('--hold and --print-now cannot be used together')
        jid = queue.submit(args.pdf, args.printer, held=args.hold)
        print(jid)
        if args.print_now:
            print(json.dumps(queue.process_one(jid, args.dry_run)))
    elif args.action == 'jobs':
        print(json.dumps(queue.jobs(args.limit), indent=2))
    elif args.action == 'history':
        print(json.dumps(queue.history(args.job), indent=2))
    elif args.action == 'hold':
        if not queue.hold(args.job):
            parser.error('Job not found or cannot be held')
        print('Held', args.job)
    elif args.action == 'release':
        if not queue.release(args.job):
            parser.error('Job not found or not held')
        print('Released', args.job)
    elif args.action == 'cancel':
        if not queue.cancel(args.job):
            parser.error('Job not found or no longer cancellable')
        print('Cancelled', args.job)
    elif args.action == 'interrupted':
        if not queue.mark_interrupted(args.job):
            parser.error('Job is not a claimed, interrupted submission')
        print('Uncertain', args.job)
    elif args.action == 'work':
        while True:
            completed = queue.process_one(dry_run=args.dry_run)
            if completed:
                print(json.dumps(completed), flush=True)
            if args.once:
                break
            if not completed:
                time.sleep(max(args.interval, 1.0))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
