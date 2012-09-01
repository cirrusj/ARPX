//
//  VendorViewData.m
//  ARPX
//
//  Created by cirrus on 8/30/12.
//  Copyright (c) 2012 cirrus. All rights reserved.
//

#import "VendorViewData.h"

@implementation VendorViewData

- (id)init {
    self = [super init];
    if (self) {
        NSString* path = [[NSBundle mainBundle] pathForResource:@"vendors" ofType:@"plist"];
        //NSLog(@"Vendor path: %@",path);
        vendorData = [NSMutableDictionary dictionaryWithContentsOfFile:path];
        //NSLog(@"Vendor Count: %lu",[vendorData count]);
        [vendorData retain];
    }
    return self;
}


- (NSInteger)numberOfRowsInTableView:(NSTableView *)aTableView {
    NSUInteger count = [[vendorData allKeys] count];
    return count;
}

- (id)tableView:(NSTableView *)aTableView objectValueForTableColumn:(NSTableColumn *)aTableColumn row:(NSInteger)rowIndex {
    NSString *columnIdentifer = [aTableColumn identifier];
    NSArray *keys = [vendorData allKeys];
    if ([columnIdentifer isEqual:@"MAC"]) {
        return [keys objectAtIndex:rowIndex];
    } else if ([columnIdentifer isEqual:@"Name"]) {
        return [vendorData objectForKey:[keys objectAtIndex:rowIndex]];
    }
    return NULL;
}

- (NSString*) vendorForMac: (NSString*) mac {
    NSArray *macArray = [mac componentsSeparatedByString:@":"];
    NSString *vendor = [NSString stringWithFormat:@"%@:%@:%@",[macArray objectAtIndex:0],[macArray objectAtIndex:1],[macArray objectAtIndex:2]];
    return [vendorData objectForKey:vendor];
}

@end
