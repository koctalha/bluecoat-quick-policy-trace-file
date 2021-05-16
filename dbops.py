import csv

#WRITING PART######################################################

def dbwTraceActive(x):

    r = csv.reader(open('db.csv'))
    lines = list(r)

    lines[1][1] = x

    writer = csv.writer(open('db.csv', 'w'))
    writer.writerows(lines)

def dbwUsername(x):

    r = csv.reader(open('db.csv'))
    lines = list(r)

    lines[2][1] = x

    writer = csv.writer(open('db.csv', 'w'))
    writer.writerows(lines)

def dbwPassword(x):

    r = csv.reader(open('db.csv'))
    lines = list(r)

    lines[3][1] = x

    writer = csv.writer(open('db.csv', 'w'))
    writer.writerows(lines)

def dbwEnablePassword(x):

    r = csv.reader(open('db.csv'))
    lines = list(r)

    lines[4][1] = x

    writer = csv.writer(open('db.csv', 'w'))
    writer.writerows(lines)

def dbwKey(x):

    r = csv.reader(open('db.csv'))
    lines = list(r)

    lines[5][1] = x

    writer = csv.writer(open('db.csv', 'w'))
    writer.writerows(lines)


#READING PART######################################################


def dbrTraceActive():
    r = csv.reader(open('db.csv'))
    lines = list(r)

    x = lines[1][1]

    return x


def dbrUsername():
    r = csv.reader(open('db.csv'))
    lines = list(r)

    x = lines[2][1]

    return x

def dbrPassword():
    r = csv.reader(open('db.csv'))
    lines = list(r)

    x = lines[3][1]

    return x

def dbrEnablePassword():
    r = csv.reader(open('db.csv'))
    lines = list(r)

    x = lines[4][1]

    return x

def dbrKey():
    r = csv.reader(open('db.csv'))
    lines = list(r)

    x = lines[5][1]

    return x