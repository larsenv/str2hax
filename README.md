# str2hax [![Original post][opBadgeImg]][opBadgeLink]

> Just to get this out of the way: **THIS DOES NOT WORK ON THE WII MINI**

Alright, so with Nintendo shutting down the E-Shop, there won't be a way of getting the Internet Channel anymore which means no more [FlashHax][flashHax].  
So we need another exploit that works without SD cards and now only works with whatever default channels are installed on the Wii.


## So what's the attack surface for the default channels?
Well luckily for us Nintendo decided to have their EULA for the Wii be updatable, and they decided to do this by making the EULA view actually just be [Opera][opera] pointed at the page `http://cfh.wapp.wii.com/eula/XXX/YY.html` where `XXX` is the country code and `YY` is the language.  
And since they get the page over `http`, that means if we change the DNS servers, then we can switch the page out for whatever we want.  
See below for the write-up.


## How to setup *str2hax*:
1. Go to the Wii's settings, then under **Internet** select **Connection Settings** and choose your currently active connection.
1. Select **Change settings** and scroll to the right until you get to **Auto-Obtain DNS**.
1. Select **No**, then select **Advanced Settings**.
1. Change the **Primary DNS** to `97.74.103.14` and the **Secondary DNS** to `173.201.71.14`.
1. Select **Confirm** and then **Save**, you will be told you must run a connection test. (Select **No** to the system update prompt)
   If the connection test doesn't work, try running it one more time and if it still fails, leave a post about it. (Please make sure you have a working internet connection in the first place.)
1. Back out to the Internet panel and choose **User Agreements**. Select **Yes** to the question about the Wii Shop Channel/WiiConnect24.
1. You will be taken to a screen telling you to review the **User Agreements** for the Wii. Select **Next**.
   If you see [a pony](./rd.png) on screen telling you to wait, then you have done everything correctly. The exploit takes 1-2 minutes (1:25 is usually how long mine takes), if it takes longer than 2 minutes then it probably failed. Just turn off your Wii and start again from step 6.

After a minute or two you should be booted into the HackMii Installer. If the Wii freezes on a with a bunch of white text on it please take a LEGIBLE picture of the screen. I can't help you if I can't read it.

If you got some use out of this and want to throw me some money you can do so here. (College is expensive, so is IDA)


## So how does *str2hax* work?

Well, it's actually [`CVE-2009-0689`][cve] as you may have guessed if you looked at the source from the page and found this `parseFloat` as the last function call.


### So what exactly is `CVE-2009-0689`?

It's a heap based buffer overflow that happens when attempting to convert large ASCII decimals to [`IEEE754`][ieee754] decimals.  
This occurs in the popular [`dtoa.c` library by David M. Gay][dtoa].  
The Opera team made some changes to it, but a close match for it can be found [here][dtoaOpera].

With the source code in hand we can get a much better idea of what's happening here.  
First we need to know why things crash when we pass in large ASCII decimals, but first we need to explain how **`dtoa`** manages its memory.  
And yes, **`dtoa`** is the one managing its memory.  
**`dtoa`** needs to expand the ASCII decimal given to its full value to be able to perform the necessary math and ensure correctness.  
To do this it allocs large structs called `Bigint`, these blocks are stored in a linked list based on the size of the decimal they can hold. (The sizes are in powers of 2)  
The format of a `Bigint` is given on line 463 and looks like this:

```c
struct Bigint {
  struct Bigint *next;
  int k, maxwds, sign, wds;
  ULong x[1];
};
```

You can see the next variable which will be a pointer to the next free `Bigint` in the list when not in use, the `k` variable which indicates how big of a number can be stored in it, the `maxwds`, `sign`, and `wds` which are used to keep track of how many words of data represent the number as well as its sign, and finally the actual number follows in the array `x`.  
So now we know how numbers are stored we need to see how these `Bigint` are kept when not in use.
You can see on line 471 that an array of `Bigint` is declared called `freelist` and is given a size of `Kmax + 1`, `Kmax` is defined to be `15` here so that means there are `16` slots for `Bigint` to occupy.  
Each index in the array points to the first `Bigint` in the linked list of free `Bigint` of size `k`.


`Kmax` is used to indicate what the maximum `k` value a number can be before the library can't handle it.
When getting these `Bigint`, **`dtoa`** uses a wrapper function called `Bmalloc`.
`Bmalloc` takes an int `k` and checks to see if there are any free `Bigint` in the `freelist` of size `k` by simply checking `freelist[k]` for a pointer and if not it allocs one with `malloc` as normal.


### So what happens if we pass in a number that results in `k` being above `Kmax`?

Well, things go wrong.  
When you index past the end of an array, you will get whatever is in memory directly after it.  
Luckily for us, `freelist` is stored in the `bss` section since it's a global variable and therefore the next global variable is probably what the compiler decided to put after `freelist`.  
This turns out to be correct and the next global variable in **`dtoa`** is the `p5s` array which is used by `pow5mult`.  
So what is in `p5s`? It's more pointers to `Bigint` actually. But very critically, it's pointers to `Bigint` of a much smaller size (2 in this case).
So, when asked for a `Bigint` of size `Kmax + 1`, instead you get back a `Bigint` of size 2. Oops!

Unfortunately **`dtoa`** is quite complicated, so I've only traced a small step of events that lead to the buffer overflow.  
When attempting to diff two large `Bigint`, **`diff`** tries to allocate a return `Bigint` that will be passed back. This return `Bigint` attempts to allocate a `k` of size 17 which is one above the maximum and thus accidentally grabs from `p5s` which at the time has a `Bigint` of size 2 sitting in it.  
**`diff`** then effectively copies ~50K of the decimal passed to it into the smaller `Bigint`. (Actually it is a **`diff`** of our original decimal and a small decimal. I can't seem to figure out it's meaning.) (Also it copies much more than 50K but that's all that's usable before it starts hitting the smaller decimal and things stop being predictable.)  
So that means that ~50K of our decimal ends up smashing through the much smaller `Bigint` (only allocated to something like `0x20` bytes), and we can control all 50K.

So now we need to figure out what to overwrite with our 50K of data.  
Unfortunately it's too big of an overwrite to ever return back to JavaScript (you might be able to, but I choose not to), so instead I decided to overwrite another `Bigint` and use its `k` value to get an arbitrary write of.  
When **`dtoa`** wants to "free" a `Bigint`, it calls a function `Bfree` which actually never frees it but instead adds it to the linked list we saw above. This is how `Bigint` are recycled.  
To do this it attempts to write a pointer to the `Bigint` to `freelist[v->k]`, which means that it will take `k` from the bigint, multiply it by 4, then add it to the memory location of freelist and write a pointer to the `Bigint` there.  
Unfortunately it also writes the current value at that address as the next pointer in the `Bigint`, which happens to be the first value.  
To make matters worse, the next field after `next` happens to be the `k` value, which means our `k` value will be tied to the next value written.  
This becomes very annoying later.

So since we control the `k` value of the `Bigint`, we can direct the write to any 4 byte aligned address. Luckily for us this version of Opera doesn't appear to use ASLR/DEP, so I chose to overwrite a return address on the stack with it.  
This results in the `Bigint` struct being jumped to and its fields being interpreted as code.  
As you may have guessed, that means we need to find a return address that not only has stored in it a valid PowerPC instruction, but whose address results in a `k` that is also valid, since we won't get code execution until both fields have been executed first.  
Very luckily just 2 layers deep in the stack a return address happens to decode to a valid load instruction with a register that is a valid address at return time and has a `k` value that is safe. This means we will safely pass over it.

Here is a more visual representation of the `Bigint` struct we overwrite:

```c
uint32_t chain_layout[] = {
  marker, // Beginning of bigint x region
  0x00000000, // End of bigint x region
  0x00000000, // Heap padding
  0x00000000, // Heap padding
  heap_header, // Heap header for next bigint block
  bigint_next, // next pointer for the following bigint
  bigint_k, // k size of the following bigint
  relative_jump, // A relative jump forward (overlaps maxwds)
  0x00000000, // sign
  0x00000000 // wds
};
```

With all this done we can now just insert a relative instruction in the `maxwds` field, safely slide down the chain of jump instructions (several fake `Bigint` were created in case we don't align things properly with heap feng shui) until we hit our payload.

In this case the payload is [**`savezelda`**][savezelda] that has had SD/gecko support removed and really just serves as an egg hunter for a bigger payload downloaded in memory.  
Due to browser memory restrictions, the whole page can't be very big (~512K), and we already take up quite a bit with the ASCII decimal.  
To work around this, the payload is [**`deflate`**][deflate]d and uncompressed by **`savezelda`** with [a very small **`deflate`** implementation][miniz] by [*Rich Geldreich*][richgel999] (Thank you VERY much).

The payload that *str2hax* currently boots is a small network loader that downloads the *HackMii Installer* and launches it.  
Random thingy: Also I didn't disable the framebuffer, so you get a nice view into RAM while *HackMii* is booting, which is why you see all the glitchy green mess.


## How do I build it?

0. Grab the source code from here: https://github.com/Fullmetal5/str2hax
0. Copy your payload (MUST BE VERY SMALL, you should probably just use the network loader) into the payload folder
0. Run `./make_is.sh YOUR_PAYLOAD.elf`  
   This will give you a `payload.png`
0. Run `./create.sh` in the main directory
0. It will create a `site.zip` file with everything you need. (Apache is required for the redirects)
0. To test this, you will need to setup a DNS server ([Dnsmasq][dnsmasq] works great) and redirect `cfh.wapp.wii.com` to your site.


[opBadgeImg]: https://img.shields.io/badge/-Original%20post-152F5A?labelColor=2A4878&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAMdSURBVDhPbVNba9tmGH70fZIlH2QnipO4debOOZY0S+hKGWMJZDR0rHQbtNCbUNhv2KC9He1+xC560d6WjZVCL0Ihoax0y0XZGhrYchj1KYltxbEtS7aO3iflwAJ9hEB6v+d93+c9fByO0GpplHBk0vO8ckyWK0dmdLuu2HWdrGW7M5btTJu2M+p6XoJypC7w9MVJgGazuaAZ5gMpxD/sU3p/8Gwz3Tbtq/VW+3q13rpUrmmp/YYuNvQOWCCcTcYxNzOiBgE8x0wUyge//LGeuzI7nV2JR8NLO9XG7Y1C5fz2jkrVuo6O5TA1XfiPIkfw5aeTO2ND/feDAGbbuPr7+rtfX/y5Fflm7iOnUDng3myWKMvO6ADhToRCFHh8PTuFqeGzP7FS7lJN0247rre4uv5uplitI79XIxuFKulYNjjm6L/H8BVMZAYxNNCDtmmNxaPSW1Jr6g82i9Wb+00DHiPUW52A/H/HY/i2XLmGn1f+QvlAIyGeN4jRsYyl1b99QyD1PX6nwBqNHjmMD1NKlSX8l8gRaVMUKGzHDQhMBFMSfJ7A/z+2sRQQKIXesQbZyCdIVArllHiUeR6ShvrCmMlEQRnJr9mXNJUOY2RAOglS19twve5uSOA3SE0zPturNYP6hpIxfJUp4Jb8BJeyMsSQgOlMAjezedwYr2M4JQdjTLKE/T2xN1QQt/we9OttC4TymP9Aw7D6CGLxKb6Qf8O5lIKF5DrERBpJycJ8ag88L4BtI1zXpX5FRIlH1vyxoOviZUlGLrkIK30Ny/os8uUDPFcvwGoUUWlLWNkdZDwP2TN9CEuhNaba5tgduKI29PtsEy8uv96SeiIcBmSCtaIJ22a7QAjOn5FY0zzoDo/PPx5tMWVLiaj0XSQaywdD67pWr9G2vl3bLt1jQWJqUwfxD/xT1ji/dylFxsLlidrkucHvRVF4zNGQcUwJwNZZYKNcLKmNO//kK+O7+03q1xpmjUz3J5yJzMDblBL/kVLuiRSOHs6c4dTadD2bcx132LSc6+wmfuJ4niJQooZF4RUb2TM+JOWOqEcA/gMUdXnkkKLw6wAAAABJRU5ErkJggg==
[opBadgeLink]: https://gbatemp.net/threads/523210/
[flashHax]: https://wii.guide/flashhax.html
[opera]: https://www.opera.com/
[cve]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-0689
[ieee754]: https://en.wikipedia.org/wiki/IEEE_754
[dtoa]: https://www.netlib.org/fp/dtoa.c
[dtoaOpera]: https://websvn.kde.org/branches/KDE/4.3/kdelibs/kjs/dtoa.cpp?revision=986143&view=markup
[savezelda]: https://github.com/lewurm/savezelda
[deflate]: https://en.wikipedia.org/wiki/DEFLATE
[miniz]: https://github.com/richgel999/miniz
[richgel999]: https://github.com/richgel999
[dnsmasq]: http://www.thekelleys.org.uk/dnsmasq/doc.html
