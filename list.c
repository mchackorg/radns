/*
 * List functions taken from the mcwm window manager released under
 * ISC license.
 *
 * See http://hack.org/mc/hacks/mcwm/
 *
 * Copyright (c) 2010,2011 Michael Cardell Widerkrantz <mc@hack.org>
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose with or without fee is hereby granted, provided that
 * the above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
 * OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdlib.h>
#include <stdio.h>
#include "list.h"

#ifdef DEBUG
#define D(x) x
#else
#define D(x)
#endif

/*
 * Create space for a new item and add it to the head of mainlist.
 *
 * Returns item or NULL if out of memory.
 */
struct item *additem(struct item **mainlist)
{
    struct item *item;
    
    if (NULL == (item = (struct item *) malloc(sizeof (struct item))))
    {
        return NULL;
    }
  
    if (NULL == *mainlist)
    {
        /* First in the list. */

        item->prev = NULL;
        item->next = NULL;
    }
    else
    {
        /* Add to beginning of list. */

        item->next = *mainlist;
        item->next->prev = item;
        item->prev = NULL;
    }

    *mainlist = item;
        
    return item;
}

void delitem(struct item **mainlist, struct item *item)
{
    struct item *ml = *mainlist;
    
    if (NULL == mainlist || NULL == *mainlist || NULL == item)
    {
        return;
    }

    if (item == *mainlist)
    {
        /* First entry was removed. Remember the next one instead. */
        *mainlist = ml->next;
    }
    else
    {
        item->prev->next = item->next;

        if (NULL != item->next)
        {
            /* This is not the last item in the list. */
            item->next->prev = item->prev;
        }
    }

    free(item);
}

void freeitem(struct item **list, int *stored,
                     struct item *item)
{
    if (NULL == list || NULL == *list || NULL == item)
    {
        return;
    }
    
    if (NULL != item->data)
    {
        free(item->data);
        item->data = NULL;
    }

    delitem(list, item);

    if (NULL != stored)
    {
        (*stored) --;
    }
}

/*
 * Delete all elements in list and free memory resources.
 */ 
void delallitems(struct item **list, int *stored)
{
    struct item *item;
    struct item *next;
    
    for (item = *list; item != NULL; item = next)
    {
        next = item->next;
        free(item->data);
        delitem(list, item);
    }

    if (NULL != stored)
    {
        (*stored) = 0;
    }    
}

void listitems(struct item *mainlist)
{
    struct item *item;
    int i;
    
    for (item = mainlist, i = 1; item != NULL; item = item->next, i ++)
    {
        printf("item #%d (stored at %p).\n", i, (void *)item);
    }
}
