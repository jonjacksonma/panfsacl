#!/usr/bin/ruby
# Project URL: https://github.com/jonjacksonma/panfsacl

require 'find'

require 'getoptlong'
USAGE_TEXT="
#{File.basename($0)} [-bkndRLPvh] [{-m|-x} acl_spec] file ...
  
DESCRIPTION

  This  utility  sets  Panasas Access  Control  Lists  (ACLs)  of files and directories.  On the command line, a sequence of commands is followed by a
  sequence of files

  Only additional access controls beyond the base entries for the owner, the group, and others are modifiable by this tool. Use chmod/chown/chgrp to change those.

  The options -m, and -x expect an ACL on the command line. The ACL entry format is described in Section ACL ENTRIES.

  The  --set option sets the ACL of a file or a directory. The previous ACL is replaced.  ACL entries for this operation must include permissions.

  The -m (--modify) option modifies the ACL of a file or directory.  ACL entries for this operation must include permissions.

  The  -x  (--remove) option removes ACL entries. It is not an error to remove an entry which does not exist.  Only ACL entries without the perms field are accepted as parameters.

MAIN OPTIONS
  -b, --remove-all
       Remove all extended ACL entries. The base ACL entries of the owner,  group  and  others  are retained.

  -i, --inherit
       ACLs set on directories using -m and -s will be inherited by future files created 

ADDITIONAL OPTIONS

  -h, --help:
     show help

  -d, --debug:
     debug mode
  
  -v, --verbose:
     print changes
     
ACL ENTRIES
  The setfacl utility recognizes the following ACL entry formats (blanks inserted for clarity):
  
  [+-][u[ser]:]uid[:perms]
    Permissions of a named user. Permissions of the file owner if uid is empty.
  
  [+-]g[roup]:gid[:perms]
    Permissions of a named group. Permissions of the owning group if gid is empty.
  
  The first symbol may be '+', indicating 'allow' or '-' indicating 'deny'. Defaults to '+'. All 'deny' ACLs take precedence over any 'allow' ACLs.
  
  For uid and gid you can specify either a name or a number.
  
  The  perms  field  is a combination of characters that indicate the permissions: read (r), write (w), execute only if the file is a directory or already has execute permission for some user (X).

EXAMPLES
  # Set only execute permission on a directory to allow user 'abc123' to traverse directory 'directory_name' but not read it

    #{File.basename($0)} -m +user:abc123:X directory_name

  # Set read-only permission for groupABC recursively to directory_name and all files in it and existing sub-directories. Files created at a later time would not have the ACL set

    #{File.basename($0)} -R -m +group:groupABC:r directory_name
  
  # Give user 'abc456' permission to read, write and execute file 'script_name' (requires script_name to already have execute permission set for the file owner)

    #{File.basename($0)} -m +u:abc456:rwX script_name

  # Give group 'groupCDE' permission to read and write to directory 'directory_name' and cause all new files or directories created under 'directory_name' to inherit this permission

    #{File.basename($0)} -i -m +g:groupCDE:rw directory_name

  # Deny permission to user 'xyz789' to read or write file 'data_file'

    #{File.basename($0)} -m -u:xyz789:rw data_file

NOTES

  Always test that the ACLs perform as expected
"
opts = GetoptLong.new(
  [ '--debug', '-d', GetoptLong::NO_ARGUMENT],
  [ '--help', '-h', GetoptLong::NO_ARGUMENT ],
  [ '--verbose', '-v', GetoptLong::NO_ARGUMENT],
  [ '--modify', '-m', GetoptLong::REQUIRED_ARGUMENT ],
  [ '--remove-all', '-b', GetoptLong::NO_ARGUMENT],
  [ '--remove', '-x', GetoptLong::REQUIRED_ARGUMENT ],
  [ '--recursive', '-R', GetoptLong::NO_ARGUMENT ],
  [ '--inherit', '-i', GetoptLong::NO_ARGUMENT ]
)

# GetoptLong::OPTIONAL_ARGUMENT
FILE_READ='rnkRP'
FILE_WRITE='wadNW'
DIR_READ='x'
DIR_WRITE='cCD'
EXEC='x'
FULL='ops'
INHERIT=',I:OICI'
# Ignoring "change ACL" "take ownership" and "sandbox" PanFS acls
# may be addd later as full owner options

@recursive=false
@debug=false
@verbose=false
@inherit=false
@remove_acls=Array.new()
@add_acls=Array.new()

def get_nid (type,identifier) 
  if identifier.match(/^[0-9]+$/)
    return identifier
  else
    puts "/usr/bin/getent #{type} #{identifier}" if @debug
    getent_line = %x( /usr/bin/getent #{type} #{identifier} )
    if $? != 0 then
      puts "Problem looking up numeric id for #{identifier}. Got #{getent_line}"
      exit(1)
    else
      return getent_line.split(':').at(2)
    end
  end
end

modify_matches=Array.new()

# Options are processed in the order provided on the command line
opts.each do |opt, arg|
  case opt
  when '--debug'
    @debug=true
  when '--verbose'
    @verbose=true
  when '--help'
    puts USAGE_TEXT
    exit(0)
  when '--inherit'
    @inherit=true
    
  when '--modify'
    mtc = arg.match(/^([+-]?)(g|group|u|user):([[:alnum:]]+):([rwX]+)$/)
    if mtc.nil? 
      STDERR.puts "#{arg} is not a valid ACL, (try --help)"
      exit(1)
    else
      modify_matches.push(mtc)
    end
    
  when '--recursive'
    @recursive=true
  when '--remove-all'
    @remove_acls.push('(uid|gid):[0-9]+')
  when '--remove'
    acl_components=arg.split(':')
    prefix=nil
    suffix=nil
    if acl_components.count == 2 then
      case acl_components[0]
      when /\A(g|group)\z/
        prefix='gid'
        type='group'
      when /\A(u|user)\z/
        prefix='uid'
        type='passwd'
      else
        puts "acl to be removed must be of the form [u[ser]:]uid or g[roup]:gid"
        exit(1)
      end
      suffix=get_nid(type,acl_components[1])
      @remove_acls.push("#{prefix}:#{suffix}")
    else
      puts "acl to be removed must be of the form [u[ser]:]uid or g[roup]:gid"
      exit(1)
    end 
  end
end

if ARGV.length == 0
  puts "Missing file argument (try --help)"
  exit 1
end

# Translate user provided ACLs to Panasas ACLs
inherit_acl = @inherit ? INHERIT : ''
modify_matches.each do |mtc|
  aclhash=Hash.new()
  sense = mtc[1] == "-" ? "-" : "+"
  type = mtc[2].start_with?('g') ? 'group' : 'passwd'
  uidtype = mtc[2].start_with?('g') ? 'gid' : 'uid'
  identifier = get_nid(type,mtc[3])
  puts identifier if @debug
  
  base_acl = ''
  base_acl += FILE_READ if mtc[4].include?('r')
  base_acl += FILE_WRITE if mtc[4].include?('w')
  
  dir_acl  = base_acl
  dir_acl += DIR_READ if mtc[4].match(/[rxX]/)
  dir_acl += DIR_WRITE if mtc[4].include?('w')
  
  base_acl += EXEC if mtc[4].include?('x')
  
  execfile_acl = base_acl
  execfile_acl += EXEC if mtc[4].match(/[xX]/)
  
  aclhash.store(:fileacl,sense + uidtype + ":" + identifier + ',' + base_acl)
  aclhash.store(:diracl,sense + uidtype + ":" + identifier + ',' + dir_acl + inherit_acl)
  aclhash.store(:execfileacl,sense + uidtype + ":" + identifier + ',' + execfile_acl)
  
  @add_acls.push(aclhash)
  @remove_acls.push("#{uidtype}:#{identifier}")
end

def modify_acl(path)
  puts "PATH: #{path}" if @debug
  write=false
  curr_acl=%x(/usr/bin/getfattr --only-values -n user.panfs.acl "#{path}" 2>/dev/null)
  if $? == 0
    puts curr_acl if @debug
    aclarr=curr_acl.split(" ")
    @remove_acls.each do | acl |
      puts "TEST: #{acl}" if @debug
      # can't operate on primary group or users - exclude any acl that ends with *
      if ! aclarr.reject! { |a| a.match(/^[+-]#{acl},[rwxacdkposCnNDRWPShH]+(,I:[OICNPD]*)?(?!\*)$/)  }.nil?
        write=true
        puts "Match found"  if @debug
      end 
    end
    if @add_acls.count > 0
      write = true
      ftype=File.ftype(path)
      # file, directory, characterSpecial, blockSpecial, fifo, link, socket, or unknown.
      case ftype
      when 'file'
        executable = File.executable?(path) 
        @add_acls.each do | aclhash |
          acl = executable ? aclhash[:execfileacl] : aclhash[:fileacl] 
          aclarr.push(acl)
        end
      when 'directory'
        @add_acls.each do | aclhash |
          aclarr.push(aclhash[:diracl])
        end
      else 
        puts "Ignoring #{tfype} at '#{path}'" if @verbose or @debug
      end

    end

    if write
      puts "/usr/bin/setfattr -n user.panfs.acl -v '#{aclarr.join(' ')}' #{path}" if @verbose or @debug
      %x(/usr/bin/setfattr -n user.panfs.acl -v '#{aclarr.join(' ')}' #{path})
    else
      puts "no change required" if @debug
    end
  else
    STDERR.puts "Failure getting ACL for #{path}"
  end
end

ARGV.each do |target|
  if @recursive
    Find.find(target) do | path |
      modify_acl(path)
    end
  else
    modify_acl(target)
  end
end
      
