---
layout: post
title: Sifting through the SPLurge! Writing Effective Queries for Splunk with SPL 
tags: splunk detections
---

Splunk is arguably one of the most popular and powerful tools across the security space at the moment, and for good reason. 
It is an incredibly powerful way to sift through and analyze big sets of data in an intuitive manner. 
SPL is the Splunk Processing Language which is used to generate queries for searching through data within Splunk.

The organization I have in mind when writing this is a SOC or CSIRT, in which large scale hunting via Splunk is likely to be conducted, though it can apply just about any where. 
It is key to be able to have relevant data sets for which to properly vet queries against. 
Fortunately, there are many example data sets available for testing on GitHub, from [Splunk](https://docs.splunk.com/Documentation/Splunk/7.1.1/SearchTutorial/GetthetutorialdataintoSplunk), and some mentioned below. 
There are also "data generators" which can generate noise for testing. Best of all would be to create your own though :).

I was fortunate to have had the enjoyable experience of participating in a Boss of the SOC CTF a few years back, which had some pretty good exemplar security related data. 
Earlier this year, they released the data set publicly [here](https://www.splunk.com/blog/2018/05/10/boss-of-the-soc-scoring-server-questions-and-answers-and-dataset-open-sourced-and-ready-for-download.html).

This guide is not meant to be a deep dive into the structuring of a query using the SPL. 
The best place for that is the Splunk documentation itself, starting with [this](http://docs.splunk.com/Documentation/Splunk/7.1.1/Search/Aboutsearchlanguagesyntax). 
This is geared more towards operations in which multiple queries are written, maintained, and used in an operational capacity. 
Many of these concepts can be generalized and applied to other signatures, rules, code or programmatic functions, such as Snort, YARA, or ELK, in which a large quantity of multi-version discrete units must be maintained.

### 1. Balance efficiency with enough specificity to minimize false positives
The ultimate goal of any Splunk query is to search and present data in order to answer some question(s). There are many right ways to search in Splunk, but there are often far fewer best ways (yes, multiple bests, see next sentence). Before formulating a search query, a couple considerations should be weighed and prioritized, such as accuracy, efficiency, clarity, integrity, and duration. It is easy to get spoiled by simply doing wildcard searches, but also just as easy to unnecessarily bog down a search with superfluous key value mappings. An over reliance of either can lead to problems.

- **Accuracy**: are there multiple sources which can answer the question? If so, which is more reliable and authoritative? More importantly, how important is it to reduce or eliminate false positives from your results? There is a heavy inverse correlation between accuracy and efficiency.
- **Clarity**: filtering down to the most relevant information needed to answer the question is only half of the battle –you still need to interpret it. It may be fine to view the results as raw data if there are only one or two results of non-complex data, but when there are rows of deeply structured data, taking the time to present it in the most appropriate manner will go a long way.
- **Duration**: the length required for the query to complete. Is this a search that will be run often, and so delays are additive and add to total inefficiency; is there an urgent need to answer something ASAP; is a longer duration eating up resources on other running functions on the search head? Sometimes it is necessary to break a search into smaller sub-searches or to target smaller sets of data and then pivot from there.
- **Efficiency**: closely tied to duration, an inefficient query will lead to unnecessary delays, excessive resource consumption, and could even effect the integrity of the data (pay close attention to implicit limitations of results on certain commands!). Paying attention to efficiency is especially important if there are per-user limitations on number of searches, memory usage, or other constraints.Too many explicitly defined wildcard placeholders could become very expensive, and the [atomicity](https://en.wikipedia.org/wiki/Linearizability) of a formulated query should always be considered.
- **Integrity**: will you be manipulating any data as part of your search? If so, understand the risks to compromising the integrity of your results in doing so. The more pivots made on returned data, the more susceptible to loss of integrity the search becomes.

### 2. Make it readable
Write queries in a consistent and clear manner. 
Sometimes it is better to have a query take up many additional lines for the sake of better readability. 
Breaking into newlines on pipes is the defacto standard for readability purposes, as can be seen below.

```python
event_simpleName IN (SyntheticProcessRollup2, ProcessRollup2) ImageFileName="*Windows\\\System32\\\\regsvr32.exe" CommandLine="*/i:http*" AND ParentCommandLine="*scrobj.dll*"
| rex field=CommandLine "/i:(?<sct_file_tmp>\S+)"
| eval sct_file=replace(sct_file_tmp, ":", "[:]")
| eval ParentProcess=ImageFileName
| eval ParentCLI=CommandLine
| eval ParentUser=UserName
| rename TargetProcessId_decimal AS ParentProcessId_decimal
| join ParentProcessId_decimal 
    [search event_simpleName IN (SyntheticProcessRollup, ProcessRollup2)
    | eval ChildProcess=ImageFileName
    | eval ChildCLI=CommandLine
    | eval ChildUser=UserName]
| table _time ParentUser ParentCLI ChildProcess ChildCLI sct_file
```

### 3. Make it extensible
Queries should be written in such a way that other people can modify it for their own adaptations or to update or expand a current one. 
Some ways to accomplish this would be using obvious variable names, readability, or even leaving in inexpensive functionality or variables which can be used for other purposes.

### 4. Make it modular
Modularity will lead to extensibility, maintainability, and resiliency. This will also increase efficiency as code reuse will be much simpler.

### 5. Make it feasible
If the query is written for the purpose of manual sifting and analysis, then 50k results is not very reasonable. 
However, if it is for stateful preservation, [alerts](http://docs.splunk.com/Documentation/Splunk/7.1.1/Alert/Aboutalerts), or [lookups](http://docs.splunk.com/Documentation/Splunk/7.1.1/Knowledge/Aboutlookupsandfieldactions), then that is more acceptable. 
Incorporating pivots on the information with subsearches and filtering or even, if necessary, breaking it up in to multiple different queries will make managing the results a surmountable task.

### 6. Make it resilient
The data can change and so can the SPL itself (or even custom commands if used), so writing queries that are less effected by potential changes is important, especially if the effects of the changes are not obvious, which could lead to a loss of integrity in the results. 
(This is where testing is also important)

### 7. Make it consistent
Having a style guide may seem like overkill, but if your operation is highly dependent on maintaining a repository of queries, it can go a long way. 
Naming conventions, spacing, line breaks, use of quotations, ordering, and style are some of the things to standardize to help with consistency.

### 8. Make it identifiable
Something as simple as:

```python
 | eval queryID=wxp-110 
```

This ID can then be printed out with the results if needed or purely used as a means to categorize and quickly identify. Naming conventions should be obvious or recognizable (wxp = Windows XP, query 110), or even mappable to the repository itself. 

### 9. Make it noob friendly
This is obviously highly dependent on your usage and organizational structure, however, it never hurts to keep queries as simple as can be, since there is always the chance that someone else will need to maintain or interpret them. 
Bonus* less time needing to train people on their purpose!

### 10. RTFM!
I am a huge proponent of RTFM (F!=field, btw) for both myself and others. 
Splunk has put a lot of effort into meticulous documentation, which is clearly reflected in the detailed and thorough documentation. 
With regards to writing SPL queries, the [search reference](http://docs.splunk.com/Documentation/Splunk/7.1.1/SearchReference/WhatsInThisManual) is your absolute best friend!

### 11. Know your data
The first two things that I tell anyone to do that is new to Splunk is to familiarize yourself with the syntax of SPL (#10) and just as importantly, to get to know how the data is structured. 
The simplest way to do this is to do a wildcard search (`*`) and start reviewing the raw results under the events tab. 
The data will usually be structure in XML or JSON. 
Initially, it will be less important to know which data was structured from [indexing](http://docs.splunk.com/Documentation/Splunk/7.1.1/Indexer/Howindexingworks), [field extractions](http://docs.splunk.com/Documentation/Splunk/7.1.1/Knowledge/ExtractfieldsinteractivelywithIFX), or other [transforms](http://docs.splunk.com/Documentation/SplunkCloud/latest/Knowledge/Configureadvancedextractionswithfieldtransforms), but may become important with more advanced searches.

![raw splunk event](https://1.bp.blogspot.com/-OWmT23ZrHCY/W0LFQ0q1gEI/AAAAAAAAGxg/j-glR3Qm0rwbDTqax_PcXAOf5SkXSXWfQCLcBGAs/s320/raw_splunk.png)

### 12. Test it
Do not ever merge a query into production ops, bless off on it, trust it, or whatever it is you do to give it legitimacy without first testing and confirmation of positive results. 
Regardless of how simple the query is, you can never guarantee that some other confounding issue isn't occurring. 
If it is a matter of missing the applicable data, well then, Try Harder! 
There are many great products out there to help with this at scale, such as Red Canary's [atomic red team](https://github.com/redcanaryco/atomic-red-team) or Mitre's [caldera](https://github.com/mitre/caldera).

### 13. Build it out piecemeal 
It can get stressful spending a lot of time on a query, only for it to not return the correct or any results, regardless of tweaking. 
The best way to build complex queries is to build them in pieces, testing as you go along. 
This is especially convenient because you can point to available data for the sake of testing to ensure positive results, and then change it as it is built out.

```python
# ensure you have data for the computer
host=ComputerA  

# ensure you have data being parsed from that computer to the CommandLine field
host=ComputerA CommandLine=*  

# search for all occurences of python in command line activity for the computer
host=ComputerA CommandLine="*python*"

...

#search for all systems where powershell spawned a python program in which 3 or more parameters are passed
host=* ParentProcess="powershell.exe" process="python.exe"
| rex field=CommandLine "(\s-{1,2})(?<flags>\S+)" max_match=0
| stats count values(flags) by host
| where count>3
| sort 0 host
```

### 14. Implement version control
The necessity of this is really dependent on the amount of queries and modifications, though it makes sense even for small quantities. 
This can be accomplished as simply as baking a version into the query itself, such as from #8 with revisions tacked on with periods (wxp-110.3) or even in its own field:

```python
 | eval version=3
```

Even better than that would be to maintain them in a database or repository such as GitHub, which gives the added benefit of stateful change representations. 
It is also possible to save searches directly in Splunk, the version control is less intuitive in this way.

### 15. Maintain multiple versions of the same thing
This doesn't just apply to older versions of the same query, but queries which may search the same thing but present it in a different manner, search a different data set, or search a different time window.

### 16. Don't reinvent the wheel
It is all too easy to blow a full 12 hour shift perfecting a query, which may not even end up working at all. 
While it is important to have these search queries catered to your specific need, it is not always necessary to MacGyver it alone. 
There are lots of great resources available to borrow ideas or techniques from, such as the Splunk blogs and forums, or you can even work with a co-worker.

### 17. Don't depend on the wheel
Counter to #16, you do not want to become over reliant on searching for help, as this could lead to running queries which may not be working as you think they are. 
This could also potentially compromise the integrity of the results. 
Worse yet, it could be an inefficient way of doing something which has caught on and persisted through the forums.

### 18. Share it
If you have written a gem or come up with a novel approach to something, share it back with the community. 
Even if the data set is different, there may still be much which can be gleaned from it. 
It also helps to drive conversations which benefit the community as a whole. 

### 19. Save it
This is such an obvious one, but in spite of that, I still constantly find myself rewriting queries that I had previously written over and over again...

### 20. REGEX! 
I don't know why I have this all the way down at #20, because this is easily one of the most powerful and important concepts for which to be able to pivot on results with. 
There are several commands where regex is able to be leveraged, but the two most significant are [regex](https://docs.splunk.com/Documentation/Splunk/7.1.1/SearchReference/Regex) and [rex](https://docs.splunk.com/Documentation/Splunk/7.1.1/SearchReference/Rex). 

Regex does exactly what it says --allows you to filter on respective fields (or _raw) using regex, which in Splunk is a [slimmed down version](https://docs.splunk.com/Documentation/Splunk/7.1.1/Knowledge/AboutSplunkregularexpressions) of PCRE. 
The rex command is much more powerful, in that it allows you to create fields based on the parsed data, which can then be used to pivot your searches on. 
You can even build it as a [multivalued field](https://docs.splunk.com/Documentation/Splunk/7.1.1/Search/Parsemultivaluefields) if more than one match occurs. 
An example of the rex command (and potentially more than one value) can be seen in the example from #13.

### 21. Know when its better to go beyond just using a search with SPL
Finally, we made it all the way to #21! Sometimes, depending on circumstance, function, and operational usage, manual searching with SPL queries is just not the best answer. 
Splunk has a lot of other functionality which can accomplish many of the same things, with less manual requirements. 
Alerts, scheduled reports, dashboards, and any of a number of apps built within or against the API allow for almost limitless capability. 
If you are struggling to maintain or achieve some of the topics annotated here, it may mean it is time to explore some of these alternative options.


### Final Thoughts
This is certainly not an all inclusive list, as there are many more practices which can apply here. 
Ultimately, it depends on the specific deployment, implementation, and usage of Splunk which should dictate exactly how you create and maintain search queries. 
This was also not meant to go too deep in the weeds on generating advanced queries (though that may come in the future), but rather a high level approach to maintaining quality and standards. 
There are many other people who are far more experienced and with much greater Splunk-fu out there, so if you have any input or insight, please feel free to reach out.
