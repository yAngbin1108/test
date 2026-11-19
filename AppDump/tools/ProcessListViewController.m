#import "ProcessListViewController.h"
#import "utils.h"
#import "MemoryEditor.h"
#import "AppDumpKernelLock.h"

@interface ProcessListViewController ()
@property (nonatomic, strong) UIActivityIndicatorView *indicator;
- (void)applyFilter:(NSString *)searchText;
@end

@implementation ProcessListViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = @"进程列表";
    self.view.backgroundColor = [UIColor systemBackgroundColor];

    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                      target:self
                                                      action:@selector(refreshTapped)];

    self.searchBar = [[UISearchBar alloc] init];
    self.searchBar.delegate = self;
    self.searchBar.placeholder = @"搜索进程名 / PID";
    self.searchBar.searchBarStyle = UISearchBarStyleMinimal;
    [self.view addSubview:self.searchBar];

    self.tableView = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    self.tableView.dataSource = self;
    self.tableView.delegate = self;
    self.tableView.rowHeight = 56;
    [self.view addSubview:self.tableView];

    self.indicator = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleLarge];
    self.indicator.center = self.view.center;
    self.indicator.hidesWhenStopped = YES;
    [self.view addSubview:self.indicator];

    [self loadProcesses];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGFloat w = self.view.bounds.size.width;
    CGFloat h = self.view.bounds.size.height;
    CGFloat top = self.view.safeAreaInsets.top;
    self.searchBar.frame = CGRectMake(0, top, w, 44);
    self.tableView.frame = CGRectMake(0, top + 44, w, h - top - 44 - self.view.safeAreaInsets.bottom);
    self.indicator.center = CGPointMake(w / 2.0, h / 2.0);
}

- (void)loadProcesses {
    [self.indicator startAnimating];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int count = 0;
        // 遍历 allproc 要读内核内存，必须和砸壳 / 内存扫描 / 沙盒重放串行。
        [AppDumpKernelLock() lock];
        proc_entry_t *list = proclist(NULL, &count);
        NSMutableArray *arr = [NSMutableArray array];
        if (list && count > 0) {
            for (int i = 0; i < count; i++) {
                NSString *name = [NSString stringWithUTF8String:list[i].name] ?: @"";
                [arr addObject:@{
                    @"pid": @(list[i].pid),
                    @"uid": @(list[i].uid),
                    @"name": name,
                    @"kaddr": @(list[i].kaddr)
                }];
            }
            free_proclist(list);
        }
        [AppDumpKernelLock() unlock];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.processes = arr;
            [self.indicator stopAnimating];
            [self applyFilter:self.searchBar.text];
        });
    });
}

- (void)refreshTapped {
    [self loadProcesses];
}

- (void)applyFilter:(NSString *)searchText {
    if (searchText.length == 0) {
        self.filteredProcesses = self.processes;
    } else {
        NSPredicate *pred = [NSPredicate predicateWithBlock:^BOOL(NSDictionary *proc, NSDictionary *bindings) {
            NSString *name = proc[@"name"];
            NSString *pidStr = [proc[@"pid"] stringValue];
            return [name rangeOfString:searchText options:NSCaseInsensitiveSearch].location != NSNotFound ||
                   [pidStr rangeOfString:searchText].location != NSNotFound;
        }];
        self.filteredProcesses = [self.processes filteredArrayUsingPredicate:pred];
    }
    [self.tableView reloadData];
}

#pragma mark - UITableViewDataSource

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.filteredProcesses.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    static NSString *cellId = @"ProcessCell";
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:cellId];
    if (!cell) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cellId];
    }
    NSDictionary *proc = self.filteredProcesses[indexPath.row];
    cell.textLabel.text = [NSString stringWithFormat:@"%@  (PID: %@)", proc[@"name"], proc[@"pid"]];
    cell.detailTextLabel.text = [NSString stringWithFormat:@"UID: %@  addr: 0x%llx", proc[@"uid"], [proc[@"kaddr"] unsignedLongLongValue]];
    cell.detailTextLabel.textColor = [UIColor secondaryLabelColor];
    return cell;
}

#pragma mark - UITableViewDelegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];

    if (indexPath.row >= (NSInteger)self.filteredProcesses.count) return;

    NSDictionary *proc = self.filteredProcesses[indexPath.row];
    NSString *name = proc[@"name"] ?: @"";
    NSString *pidStr = [proc[@"pid"] stringValue];
    NSString *uidStr = [proc[@"uid"] stringValue];

    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:[NSString stringWithFormat:@"%@ (PID: %@)", name, pidStr]
                                                                   message:nil
                                                            preferredStyle:UIAlertControllerStyleActionSheet];

    __weak typeof(self) weakSelf = self;

    [sheet addAction:[UIAlertAction actionWithTitle:@"修改内存"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        SKMemoryEditorViewController *ed =
            [[SKMemoryEditorViewController alloc] initWithPID:(pid_t)[proc[@"pid"] intValue]
                                                  processName:name];
        [weakSelf.navigationController pushViewController:ed animated:YES];
    }]];

    [sheet addAction:[UIAlertAction actionWithTitle:@"结束进程"
                                              style:UIAlertActionStyleDestructive
                                            handler:^(UIAlertAction *action) {
        [weakSelf killProcess:proc[@"pid"] name:name];
    }]];

    [sheet addAction:[UIAlertAction actionWithTitle:@"复制 PID"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [UIPasteboard generalPasteboard].string = pidStr;
        [weakSelf toast:[NSString stringWithFormat:@"已复制 PID: %@", pidStr]];
    }]];

    [sheet addAction:[UIAlertAction actionWithTitle:@"复制 UID"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *action) {
        [UIPasteboard generalPasteboard].string = uidStr;
        [weakSelf toast:[NSString stringWithFormat:@"已复制 UID: %@", uidStr]];
    }]];

    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];

    UITableViewCell *cell = [tableView cellForRowAtIndexPath:indexPath];
    sheet.popoverPresentationController.sourceView = cell ?: self.view;
    sheet.popoverPresentationController.sourceRect = cell ? cell.bounds : self.view.bounds;
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)killProcess:(NSNumber *)pidNumber name:(NSString *)name {
    pid_t pid = (pid_t)pidNumber.intValue;

    if (pid <= 0) {
        [self toast:@"不能结束内核进程 (PID 0)"];
        return;
    }
    if (pid == getpid()) {
        [self toast:@"不能结束自身进程"];
        return;
    }

    // crash_proc() writes a bogus stack pointer into every thread of the target
    // through the kernel. Doing that to a process that is already exiting — or
    // doing it repeatedly in quick succession — raises the chance of hitting a
    // stale proc/thread and corrupting kernel memory. Require a confirmation
    // and enforce a cooldown between kills.
    static NSTimeInterval lastKill = 0;
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    if (now - lastKill < 1.5) {
        [self toast:@"操作过于频繁，请稍候再试"];
        return;
    }

    UIAlertController *confirm = [UIAlertController
        alertControllerWithTitle:[NSString stringWithFormat:@"结束 %@？", name]
                         message:[NSString stringWithFormat:
                                  @"PID %d\n\n系统守护进程被结束后会被 launchd 自动重新拉起，反复结束可能导致内核不稳定。", pid]
                  preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf = self;
    [confirm addAction:[UIAlertAction actionWithTitle:@"结束" style:UIAlertActionStyleDestructive
                                             handler:^(UIAlertAction *a) {
        lastKill = [NSDate date].timeIntervalSince1970;
        // Serialise with every other kernel user. SKSandboxKeeper re-applies
        // sbx_escape() on a timer and that mutates kernel memory, so running it
        // concurrently with this write is a real corruption risk.
        [AppDumpKernelLock() lock];
        int krc = killprocbypid(pid);
        [AppDumpKernelLock() unlock];
        if (krc == 0) {
            [weakSelf toast:[NSString stringWithFormat:@"已结束 %@ (PID %d)", name, pid]];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.8 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [weakSelf loadProcesses];
            });
        } else {
            [weakSelf toast:[NSString stringWithFormat:@"结束失败 (PID %d)", pid]];
        }
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

- (void)toast:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:nil
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [self presentViewController:alert animated:YES completion:^{
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            [alert dismissViewControllerAnimated:YES completion:nil];
        });
    }];
}

#pragma mark - UISearchBarDelegate

- (void)searchBar:(UISearchBar *)searchBar textDidChange:(NSString *)searchText {
    [self applyFilter:searchText];
}

- (void)searchBarSearchButtonClicked:(UISearchBar *)searchBar {
    [searchBar resignFirstResponder];
}

@end
