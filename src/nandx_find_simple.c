/*
 * Copyright (C) 2013 - MonkWorks, LLC
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; see the file COPYING. If not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * NAND Xplore Find Tool Module
 *
 * Author: Josh 'm0nk' Thomas <m0nk.omg.pwnies@gmail.com>
 *
 */


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * 
 * Notes from m0nk - 
 * 
 * While it might work unmodified on other devices, this was crafted specifically
 * to work with the Sony Xperia Arc S phones.  On other devices, YMMV...
 * ===============================================================================
 * DEVICE INFO:
 *  The Sony Ericson Xperia Arc S
 *	  	Model Number: 		LT18a
 *	  	Android Version: 	4.0.4
 *	  	Baseband Version: 	8x55A-AAABQQAZM-203028G-77
 *	  	Kernel Version: 	2.6.32.9-perf \ BuildUser@BuildHost#1
 *	  	Build Number:		4.1.B.0.587
 * Kernel source from Sony available at:
 *	  	http://developer.sonymobile.com/downloads/xperia-open-source-archives/open-source-archive-for-build-4-1-b-0-587/
 * ===============================================================================
 *	
 * Unless marked in comments as written by me, the below methods and defines are 
 * stolen / modified from the following mtd subsystem components:     
 * 	.../mtd/tests
 *  	.../mtd/
 *  	.../kernel/include/linux/mtd/mtd.h
 *
 * I attempt to inline cite the original file_name / author where applicable if 
 * the only changes I made were logging things. I do this to be polite and to give you
 * a place to look if you are wanting to jump around in kernel memory instead of compiling.
 *
 * In an attempt to make the source easier to read I also tried to add notes 
 * to explain things along the way.
 * 
 * To follow the "letter of the linux law", this file is GPL v2
 *
 *
 * Have fun and please play nice with one another, the entire point of this research 
 * is academic exploration for advancing overall awareness of hardware security.
 *
 * -m0nk
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/err.h>
#include <linux/mtd/mtd.h>
#include <linux/sched.h>

#define PRINT_PREF KERN_INFO "nandx_find_simple: "

static int dev;
module_param(dev, int, S_IRUGO);
MODULE_PARM_DESC(dev, "MTD device number to use");

static struct mtd_info 	*mtd;
static unsigned char 	*bbt;

static int pgsize;
static int ebcnt;
static int pgcnt;


/* *******************
 * NANDX Call: nandx_map_bad_blocks
 *  Scans the NAND hardware searching for Bad Blocks,
 *  Makes a map and returns. (Totally rocket science here)
 *
 * @return (int) - Count of how many bad blocks we found
 * m0nk wrote me!
 * ******************* */ 
static int nandx_map_bad_blocks(void)
{
  int i, bad = 0;
  
  for (i = 0; i < ebcnt; ++i) {
    
    bbt[i] = mtd->block_isbad(mtd, (i * mtd->erasesize) );
    
    if (bbt[i])
      bad += 1;
    cond_resched();
  }
  
  return bad;
}

/* *******************
 * NANDX Call: nand_find_simple
 *   This basically spins up the module and runs the BBT scan.
 *   We have the option of printing out the overall hardware 
 *   info at the same time if we want.
 * 
 * m0nk wrote me!
 * ******************* */ 
static void nand_find_simple(void)
{
  uint64_t tmp;
  int err, i;
  int bad = 0;
  
  printk(KERN_INFO "\n");
  printk(KERN_INFO "=================================================\n");
  printk(PRINT_PREF "NANDX Find for MTD device: %d\n", dev);
  
  //Just grabbing a reference to the NAND device.
  mtd = get_mtd_device(NULL, dev);
  
  //Typical "if we fail" protections
  if (IS_ERR(mtd)) {
    err = PTR_ERR(mtd);
    printk(PRINT_PREF "error: Cannot get MTD device\n");
    return;
  }
  
  if (mtd->writesize == 1) {
    printk(PRINT_PREF "not NAND flash, assume page size is 512 bytes.\n");
    pgsize = 512;
  } else
    pgsize = mtd->writesize;
  
  
  //This section can go away if we want.  Since this will be running sporadically, we probably don't need the full stats every time.
    tmp = mtd->size;
    do_div(tmp, mtd->erasesize);
    ebcnt = tmp;
    pgcnt = mtd->erasesize / mtd->writesize;
    
    printk(PRINT_PREF "MTD device\n\tsize %llu\n\teraseblock size %u\n\t"
    "page size %u\n\tcount of eraseblocks %u\n\tpages per "
    "eraseblock %u\n\tOOB size %u\n\n",
    (unsigned long long)mtd->size, mtd->erasesize,
	   pgsize, ebcnt, pgcnt, mtd->oobsize);
    //end of going away code
    
    
    //We need to ensure our custom BBT has a place to live in memory!
    bbt = kmalloc(ebcnt, GFP_KERNEL);
    if (!bbt) {
      printk(PRINT_PREF "error: cannot allocate memory\n");
      return;
    }
    memset(bbt, 0 , ebcnt);
    
    //Scanning each block looking for bad ones
    bad = nandx_map_bad_blocks();
    
    printk(PRINT_PREF "scanned %d eraseblocks, %d are bad\n", ebcnt, bad);
    
    /*
     * To make this really clean, I am only printing out the bad blocks 
     * if they exist.
     */
    if( bad >= 1) {
      printk(KERN_INFO "=================================================\n");
      printk(PRINT_PREF "MTD block MAP for device: %d\n", dev);
      for (i = 0; i < ebcnt; ++i) {
	if (bbt[i])
	  printk(PRINT_PREF "block %d is BAD\n", i);
      }
      printk(KERN_INFO "\n");
      printk(KERN_INFO "=================================================\n");
    }
    
    //Cleaning up our messes  
    kfree(bbt);
    put_mtd_device(mtd);
    
    printk(KERN_INFO "=================================================\n");
    
}

// === Boring KMod stuff === //
/* *******************
 * 
 * Everything below here is typical boring kernel module stuff
 *
 * ******************* */ 
static int __init nandx_find_simple_init(void)
{
  //DO: all the things!
  nand_find_simple();
  
  return 0;
  
}
module_init(nandx_find_simple_init);

static void __exit nandx_find_simple_exit(void)
{
  return;
}
module_exit(nandx_find_simple_exit);

MODULE_DESCRIPTION("NAND Xplore Find Simple Module");
MODULE_AUTHOR("Josh 'm0nk' Thomas");
MODULE_LICENSE("GPL");





