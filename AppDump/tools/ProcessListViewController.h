#import <UIKit/UIKit.h>

@interface ProcessListViewController : UIViewController <UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate>
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) UISearchBar *searchBar;
@property (nonatomic, strong) NSArray *processes;
@property (nonatomic, strong) NSArray *filteredProcesses;
@end
