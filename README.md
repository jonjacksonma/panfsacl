# panfsacl
Panasas^ file system (PanFS^) Access Control List (ACL) cli utilities

The Panasas filesystem, commonly used in high performance computing environments, supports access control lists (ACLs, https://en.wikipedia.org/wiki/Access_control_list) which are stored as Extended File Attributes in a proprietary format.  PanFS ACLs support inheritance and more granular permissions than the typical Posix ACLs supported by most Linux filesystems.  The tools in this project simplify working with PanFS ACLs by reducing permission options to READ, WRITE, EXECUTE and INHERIT and providing a way to get and set ACLs similar to the equivalent tools for Posix ACLs.

System Requirements
  * Linux
  * Ruby
  * Linux utilities getfacl, getfattr and setfattr

^ Panasas and PanFS are trade marks of https://www.panasas.com/. This project is not affliliated with or endorsed by Panasas
