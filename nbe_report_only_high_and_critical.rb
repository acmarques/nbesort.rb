#!/usr/bin/ruby
"""
@Author	:	Antonio Marques
@Date	:	July 8, 2011
@Name	:	nbe_report_only_high_and_critical.rb
@Desc	:	This takes a nessus NBE file and prints out only 
        high and critical vulnerabilities.
@Usage	:	ruby nbe_report_only_high_and_critical.rb <nessus nbe output>
"""

puts """
  ____________ 
 < Nessus report. Only High and Critical vulnerabilities listed. >
  ------------
"""
if ARGV.size != 1 then
	puts "Usage: ruby nbesort.rb <nessus nbe>"
	exit
end
                                                               
# global finding db
$findings = Hash.new {|h, k| h[k] = Array.new}

filename = ARGV[0]
puts "[-] opening #{filename}"
f = File.open(filename, "r") # user input

f.each_with_index do |line, index|
	# don't do any of this if the line is nil
	if line != nil then
		# regex out IP, finding synopsis
		host = line.scan(/results\|[^\|]+/)[0]
		if host
			p1 = line.index("|")
			p2 = line[(p1 + 1)..line.size].index("|") + p1 + 1
			p3 = line[(p2 + 1)..line.size].index("|") + p2 + 1
			host = line[p2 + 1..p3 - 1]
			host = host + ' -- ' + line.scan(/\d+\/tcp/)[0] if line.scan(/\d+\/tcp/)[0]
		end
		if line.include?('Synopsis :') then		
			title = line.scan(/Synopsis :\\n\\n([^\\]+)/)[0] #/
			description = line.scan(/Description :\\n\\n([^\\]+)(\\n)*([^\"]*)\\n\\n/)[0] 
			
			risk_factor = line.scan(/Risk factor :\\n\\n([^\\]+)/)[0]
			risk_factor = risk_factor.first
			
			title.push("Description: #{description.join.gsub("\\n", " ") if description}") 
			title.push("\nRisk: #{risk_factor}\n\n") 
		end
		line.scan(/\d+\/tcp/)[0]
		# add to the database
		$findings[title].push(host) if host and title and (risk_factor.downcase.include? "high" or risk_factor.downcase.include? "critical")
		host = nil
		title = nil
		risk_factor = nil
	end
end

# are we done? spit out info :D
$findings.each do |key, value|
  print "\n\n>>>> "
  puts key
  value.each do |e|
    print "=> "
    puts e
  end
  puts 
end

