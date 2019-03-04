#!/usr/bin/env python

import subprocess
import logging
import sys
import time
import datetime

#logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
LOGGER = logging.getLogger(__name__)

COMMAND = 'iptables -L -v -n'
COMMAND_NAT = 'iptables -L -v -n -t nat'
SPLIT_SECONDS = 10


'''
Sort all the lines of an iptables output by chain name.
All the lines that belong to a chain are stored in a
a list, the lists are returned in a dictionary with the
chain names as keys.

Examples of lines:

Chain docker-elasticsearch (1 references)
  pkts bytes target     prot opt in     out     source               destination         
     2   128 RETURN     all  --  *      *       999.666.0.0/16       0.0.0.0/0           
   283 16980 RETURN     all  --  *      *       999.777.0.0/16       0.0.0.0/0           
     0     0 RETURN     all  --  *      *       999.888.29.0/24      0.0.0.0/0                    
     6   240 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0 

:param all_lines: List of strings, contains all the lines
    from an iptables output.
:return: Dictionary containing, for every chain name, the
    list of lines.
'''
def sort_all_lines(all_lines):
    result = dict()
    start_line = 0
    stop = False

    while not stop:
        chain_name, line_no = go_to_next_chain(start_line, all_lines)
        if line_no is None:
            stop = True
            LOGGER.debug('Stopping...')
            break
        lines_of_chain, start_line = get_lines_of_this_chain(line_no+1, all_lines)
        result[chain_name] = lines_of_chain

    return result

'''
Make a list of all strings in the list, until
a string is found that indicates the next chain.

:param start_line: The line index where to start looking.
:param all_lines: The list of strings to filter.
:return: Tuple: The filtered of strings, and the index
    of the line where the next chain starts.
'''
def get_lines_of_this_chain(start_line, all_lines):

    res_list = []
    LOGGER.debug('Checking lines starting at %s' % start_line)
    
    for i in xrange(start_line, len(all_lines)):
        nextline = all_lines[i]
    
        if is_chain_name(nextline):
            LOGGER.debug("Stopping here. Found next chain at line %s: %s\n" % (i, nextline))
            break
    
        elif not nextline=='':
            res_list.append(nextline)
            LOGGER.debug("Added %s: %s" % (i, nextline))
    
    return res_list, i


def is_chain_name(oneline):
    if oneline.startswith('Chain '):
        tmp = oneline.split(' ')
        chain_name = tmp[1]
        return True
    return False

'''
Helper.
Iterate over the strings in a list, starting at the
i'th one, until you found a string like this:

Chain docker-elasticsearch (1 references)

:param start_line: First string to be checked.
:param list_of_lines: List of strings.
:return: Tuple: The chain name and the index of the
    string, or None, None if no more matching strings
    are found.
'''
def go_to_next_chain(start_line, list_of_lines):
    for i in xrange(start_line, len(list_of_lines)):
        if list_of_lines[i].startswith('Chain '):
            tmp = list_of_lines[i].split(' ')
            chain_name = tmp[1]
            LOGGER.debug('Found chain %s at line %s' % (chain_name, i))
            return chain_name, i
    LOGGER.debug('Found no more chain...')
    return False, None


'''
Compare all chains.

:param res1: Dictionary containing, for every chain name, the
    list of lines. First run.
:param res2: Dictionary containing, for every chain name, the
    list of lines. Second run.
:return: True if no changes, False if changes. Note: The main
    output of this function is the results printed to the logger.
'''
def compare_chains(res1, res2):

    chnames1 = res1.keys()
    chnames2 = res2.keys()
    chnames = chnames1
    no_changes = True
    equal_chains = []

    if not (chnames1 == chnames2):
        LOGGER.warn("Chain names not the same - rules were added or removed!")
        chnames = set(chnames1, chnames2)

    # Look at all chains and compare:
    LOGGER.info('Found chains: %s' % ', '.join(chnames))
    for chname in chnames:
        
        # Normal case: Chain exists before and after:
        if chname in chnames1 and chname in chnames2:
            equal = compare_chain(chname, res1[chname], res2[chname])
            if equal:
                equal_chains.append(chname)
            else:
                no_changes = False

        # Rare case: Only exists BEFORE:
        elif chname not in chnames2:
            LOGGER.info('__________________________')
            LOGGER.info('Comparing chain %s' % chname)
            LOGGER.warn('No rules found in second check. They were removed before the second check.')
            no_changes = False
            for line in res1[chname]:
                LOGGER.info('Removed: %s' % line)

        # Rare case: Only exists AFTER:
        elif chname not in chnames1:
            LOGGER.info('__________________________')
            LOGGER.info('Comparing chain %s' % chname)
            LOGGER.warn('No rules found in first check. They were new in second check.')
            no_changes = False
            for line in res2[chname]:
                LOGGER.info('New: %s' % line)

    # Log those that did not change:
    if no_changes:
        LOGGER.info('RESULT: No changes at all.')
    elif len(equal_chains) > 0:
        LOGGER.info('__________________________')
        LOGGER.info('No changes in chains:')
        for chname in equal_chains:
            LOGGER.info(' * %s' % chname)
        LOGGER.info('RESULT: Some chains have changes, some not.')
    else:
        LOGGER.info('RESULT: All chains have changed.')





'''
Compare one chain, i.e. find those entries that are
equal, those that are nearly-equal (i.e. a substring
is equal) and those that are not equal at all.

When comparing iptables, the latter onyl happens if
rules were changed in the mean-time.

:param chname: Name of the chain (only for output).
:param list1: List of strings, which are the rules of that chain, before.
:param list2: List of strings, which are the rules of that chain, after.
:return: True if no changes, False if changes. Note: The main output
    of this function is the results printed to the logger.
'''
def compare_chain(chname, list1, list2):

    # Check if whole chain is equal:
    if list1 == list2:
        LOGGER.debug('No changes.')
        return True

    # Find the equal pairs (if any):
    pairs, leftovers1, leftovers2 = compare_lists(list1, list2)

    # Just a check:
    if  len(pairs)==len(list1):
        LOGGER.warn('No changes! Should have been found before. Programming error.')
        return True

    LOGGER.info('__________________________')
    LOGGER.info('Comparing chain %s' % chname)
    # Go through non-equal lines and try to find pairs
    # based on substring.
    # Using substring from 2 to end, to exclude the first
    # tow parts, which are "bytes" and "packets", which are
    # exactly those that we want to see change.
    if len(leftovers1)>0 or len(leftovers2)>0:
        LOGGER.debug('Found lines that changed. Not matched yet:')
        LOGGER.debug('Before:   %s' % '\n'.join(leftovers1))
        LOGGER.debug('After:    %s' % '\n'.join(leftovers2))

        # Find the matching pairs (if any)
        pairs, leftovers1, leftovers2 = compare_substrings(leftovers1, leftovers2, 2, None)

        # Pairs (pairs that differ only in bytes and packets):
        if len(pairs) > 0:
            LOGGER.info('Found nearly-equal pairs:')
            for pair in pairs:
                LOGGER.info('Before:   %s' % pair[0])
                LOGGER.info('After:    %s' % pair[1])

        # Non-pairs (could not be matched at all):
        # This should not happen at all!
        if len(leftovers1) > 0 or len(leftovers2) > 0:
            LOGGER.warn('No pairs:')
            for l in leftovers1:
                LOGGER.warn('Before:   %s' %l)
            for l in leftovers2:
                LOGGER.warn('After:    %s' %l)
    
    return False


'''
Compare two lists of strings and try to find
nearly-equal strings in both lists. Nearly-equal means
that substrings are equal. The substrings that are
compared are the words defined by "fro" and "to", after
splitting a string by white space.

By default, the entire string is compared.

:param lines_A: List of strings to match against the other list.
:param lines_B: List of strings to match against the other list.
:param fro: Integer, start index f the substring to compare.
    Defaults to None.
:param to: Integer, end index of the substring to compare.
    Defaults to None.
:return: A triple of the nearly-equal strings (list of
    tuples with both strings), the leftovers in the first
    list, and the leftovers in the 2nd list.
'''
def compare_substrings(lines_A, lines_B, fro=None, to=None):

    pairs_tuples = []
    tmp_A = lines_A[:]
    tmp_B = lines_B[:]

    for line_A in lines_A:
        substring_A = line_A.split()[fro:to]
        LOGGER.debug('Matching substring... %s' % substring_A)
    
        for line_B in lines_B:
            substring_B = line_B.split()[fro:to]
            LOGGER.debug(' ... with substring: %s' % substring_B)

            if substring_A == substring_B:

                tmp_A.remove(line_A)
                tmp_B.remove(line_B)
                pairs_tuples.append( (line_A, line_B) )
                
                LOGGER.debug('Found pair!')
                LOGGER.debug('   Before: %s' % line_A)
                LOGGER.debug('   After : %s' % line_B)

    return pairs_tuples, tmp_A, tmp_B

'''
Compare two lists of strings and try to find
equal strings in both lists.

Probably easier to implement with some remove-function...

:param list1: List of strings to match against the other list.
:param list1: List of strings to match against the other list.
:return: A triple of the equal strings, the leftovers
         in the first list, and the leftovers in the 2nd
         list.
'''
def compare_lists(list1, list2):

    equal_matches = []
    leftovers1 = list1[:]
    leftovers2 = list2[:]
    
    # Find the ones eual in both lists:
    for line in list1:
        LOGGER.debug('Check       %s' % line)
        
        for cand in list2:
            LOGGER.debug('Against     %s' % cand)
            
            if line == cand:
                LOGGER.debug('Found pair: %s' % line)

                equal_matches.append(line)
                leftovers1.remove(line)
                leftovers2.remove(line)
                break #  break inner loop

    return equal_matches, leftovers1, leftovers2








if __name__  == '__main__':

    # Get input
    WAIT_SECONDS = None
    if len(sys.argv) > 1:
        
        if sys.argv[1] == 'nat':
            LOGGER.info('Found keyword "nat"')
            COMMAND=COMMAND_NAT

        elif sys.argv[1].isdigit():
            WAIT_SECONDS = int(sys.argv[1])

    if len(sys.argv) > 2:
        
        if sys.argv[2] == 'nat':
            LOGGER.info('Found keyword "nat"')
            COMMAND=COMMAND_NAT

        elif sys.argv[2].isdigit():
            WAIT_SECONDS = int(sys.argv[2])

    # First run
    t1 = datetime.datetime.now()
    LOGGER.info('Command to be run: %s' % COMMAND)
    LOGGER.info('Getting iptables stats (%s)...' % t1.strftime('%Y-%m-%d_%H:%M'))
    try:
        iptables_stats_before = subprocess.check_output(COMMAND, shell=True)
    except subprocess.CalledProcessError as e:
        LOGGER.warn("Could not run '%s'." % COMMAND)
        LOGGER.error(e)
        LOGGER.info("Maybe try sudo?")
        print(str(e))
        print("Maybe try sudo?")
        code = int(str(e).split()[-1])
        exit(code)

    # If user did not specify anything, wait eternally.
    if WAIT_SECONDS is None:
        LOGGER.info('Waiting indefinitely... Please stop with CTRL-C.')
        try:
            while True:
                time.sleep(SPLIT_SECONDS)
        except KeyboardInterrupt:
            LOGGER.info('Stopped by user (KeyboardInterrupt)')
            pass

    # Wait as many seconds as the user specified.
    else:
        LOGGER.info('Waiting for %s seconds.' % (WAIT_SECONDS))
        for i in xrange(WAIT_SECONDS*SPLIT_SECONDS):
            LOGGER.debug('Sleep %s' % (1.0/SPLIT_SECONDS))
            time.sleep(1.0/SPLIT_SECONDS)

    # Second run
    t2 = datetime.datetime.now()
    LOGGER.info('Getting iptables stats again (%s)...' % t2.strftime('%Y-%m-%d_%H:%M'))
    iptables_stats_after = subprocess.check_output(COMMAND, shell=True)

    # Sort and compare results
    LOGGER.debug('Sorting the results...')
    dict1 = sort_all_lines(iptables_stats_before.split('\n'))
    dict2 = sort_all_lines(iptables_stats_after.split('\n'))
    LOGGER.info('Changes (in interval %s):' % str(t2-t1))
    no_changes = compare_chains(dict1, dict2)

    #LOGGER.info('TEST:')
    #compare_lists(['a','b','c','f'],['c','a','d','e'])
    #
    #LOGGER.info('TEST:')
    #test1 = ['0     0 RETURN     all  --  *      *       83.163.127.252       0.0.0.0/0','0     0 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0','0     0 RETURN     all  --  *      *       73.163.127.252       0.0.0.0/0']
    #test2 = ['0     0 RETURN     all  --  *      *       83.163.127.252       0.0.0.0/0','1     5 DROP       all  --  *      *       0.0.0.0/0            0.0.0.0/0','0     0 RETURN     all  --  *      *       73.163.1227.252       0.0.0.0/0']
    #compare_lists(test1, test2)


