//
//  NSNewTableView.m
//  ARPX
//
//  Created by cirrus on 8/31/12.
//  Copyright (c) 2012 cirrus. All rights reserved.
//

#import "NSNewTableView.h"
#import "ARPList.h"

@implementation NSNewTableView

- (void)keyDown:(NSEvent *)theEvent {
    unichar key = [[theEvent charactersIgnoringModifiers] characterAtIndex:0];
    if(key == NSDeleteCharacter)
    {
        [self deleteItem];
        return;
    }
    
    [super keyDown:theEvent];
}

- (void)deleteItem
{
    if ([self numberOfSelectedRows] == 0) return;
    NSInteger selected = [self selectedRow];

    ARPList *list = [self dataSource];
    //For multiple items selection
    //[selected enumerateIndexesUsingBlock:^(NSUInteger idx, BOOL *stop) {
    NSTableColumn *column = [[[NSTableColumn alloc] initWithIdentifier:@"IP"] autorelease];
    NSString *selectedIP = [list tableView:self objectValueForTableColumn:column row:selected];
    [list removeIP:selectedIP];
    //[self deselectAll:nil];
    [self reloadData];
    //}];
    
}

@end
