struct item
{
    void *data;
    struct item *prev;
    struct item *next;
};

/*
 * Create space for a new item and add it to the head of mainlist.
 *
 * Returns item or NULL if out of memory.
 */
struct item *additem(struct item **mainlist);

/*
 * Delete item from list mainlist.
 */ 
void delitem(struct item **mainlist, struct item *item);

/*
 * Print all items in mainlist on stdout.
 */ 
void listitems(struct item *mainlist);