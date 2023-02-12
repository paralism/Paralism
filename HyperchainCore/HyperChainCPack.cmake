#Copyright 2016-2019 hyperchain.net (Hyperchain)
#Distributed under the MIT software license, see the accompanying
#file COPYING or https://opensource.org/licenses/MIT.

#Permission is hereby granted, free of charge, to any person obtaining a copy of this 
#software and associated documentation files (the "Software"), to deal in the Software
#without restriction, including without limitation the rights to use, copy, modify, merge,
#publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
#to whom the Software is furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all copies or
#substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
#INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
#PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE

#FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
#OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#DEALINGS IN THE SOFTWARE.

#
#Installation package setting
#
if( DEFINED PACK_HYPERCHAIN )
	set(APPLICATION_SHORTNAME "Hyperchain-Lite")
	set(APPLICATION_DISPLAY_SHORTNAME "Hyperchain")
	set(CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}/logo-hc.ico")
	set(CPACK_IFW_PACKAGE_WATERMARK "${CMAKE_SOURCE_DIR}/watermark-hc.png")
else()
	set(APPLICATION_SHORTNAME "Paralism-Lite")
	set(APPLICATION_DISPLAY_SHORTNAME "Paralism")
	set(CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}/logo.ico")
	set(CPACK_IFW_PACKAGE_WATERMARK "${CMAKE_SOURCE_DIR}/watermark.png")
endif()


set(APPLICATION_DOMAIN "hyperchain.net" )

include( VERSION.cmake )

set( CPACK_PACKAGE_VERSION_MAJOR  ${MIRALL_VERSION_MAJOR} )
set( CPACK_PACKAGE_VERSION_MINOR  ${MIRALL_VERSION_MINOR} )
set( CPACK_PACKAGE_VERSION_PATCH  ${MIRALL_VERSION_PATCH} )
set( CPACK_PACKAGE_VERSION_BUILD  ${MIRALL_VERSION_BUILD} )
set( CPACK_PACKAGE_VERSION  ${MIRALL_VERSION_FULL})

set( CPACK_PACKAGE_FILE_NAME  ${APPLICATION_SHORTNAME}-${CPACK_PACKAGE_VERSION} )

set( CPACK_PACKAGE_DESCRIPTION_FILE  "${CMAKE_SOURCE_DIR}/README.md" ) 	# File used as a description of a project     /path/to/project/ReadMe.txt
set( CPACK_PACKAGE_DESCRIPTION_SUMMARY  ${APPLICATION_SHORTNAME} ) 		# Description summary of a project
set( CPACK_PACKAGE_INSTALL_DIRECTORY  ${CPACK_PACKAGE_FILE_NAME} )     	# Installation directory on the target system -> C:\Program Files\${CPACK_PACKAGE_FILE_NAME}
set( CPACK_PACKAGE_INSTALL_REGISTRY_KEY ${APPLICATION_SHORTNAME} )  	# Registry key used when installing this project  CMake 2.5.0
set( CPACK_PACKAGE_NAME  ${APPLICATION_SHORTNAME} ) 					# Package name, defaults to the project name
set( CPACK_PACKAGE_HOMEPAGE_URL  "http://${APPLICATION_DOMAIN}" )   	# Package URL for update
set( CPACK_PACKAGE_VENDOR  "Hyperchain" )   				# Package vendor name



#set(CPACK_SET_DESTDIR true)
#set(cpack_packaging_install_prefix /var/)

#Should use -G to specify the generator type
#set( CPACK_GENERATOR "RPM")


if(UNIX)
	set(CPACK_IFW_TARGET_DIRECTORY  "/var/${CPACK_PACKAGE_FILE_NAME}")
	set(CPACK_PACKAGING_INSTALL_PREFIX "/var/${CPACK_PACKAGE_FILE_NAME}")
	set(CPACK_RPM_PACKAGE_NAME ${APPLICATION_SHORTNAME})
else()
	set(CPACK_IFW_TARGET_DIRECTORY  "C:/${CPACK_PACKAGE_FILE_NAME}")
endif()

message(STATUS "Install IFW configuration: ${CPACK_IFW_TARGET_DIRECTORY}")

#already define in CMakeLists.txt
set(CORECOMPONET "HyperChain")

if(PACK_GUI)
set(GUICOMPONET "GUI")
endif()

set(CPACK_COMPONENTS_ALL ${CORECOMPONET} ${GUICOMPONET})

message(STATUS "Install components all: ${CPACK_COMPONENTS_ALL}")

#${CMAKE_BUILD_TYPE} settings decide how to choose files(Debug/Release) will be put into package, more see cmake_install.cmake
install(CODE "set(CMAKE_INSTALL_CONFIG_NAME \"${CMAKE_BUILD_TYPE}\")
    message(STATUS \"Current install configuration: \${CMAKE_INSTALL_CONFIG_NAME}\")" COMPONENT ${CORECOMPONET})

# Directory for the installed files.  - needed to provide anything to avoid an error# CPACK_INSTALL_COMMANDS  Extra commands to install components.
set( CPACK_TOPLEVEL_TAG "unused" ) 

# License file for the project, used by the STGZ, NSIS, and PackageMaker generators.
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")

#Wizard style to be used (“Modern”, “Mac”, “Aero” or “Classic”).
set(CPACK_IFW_PACKAGE_WIZARD_STYLE "Modern")


include(CPack)
include(CPackIFW)

cpack_add_install_type(Full DISPLAY_NAME "Everything")

set(Paralism_Core_Desc "1.Hyperchain core protocol stack.\n
	2.Application Program Interface:\n
		Command line tool, RESTful API and RPC interface
	3.System Modules:\n
		Content data proof of existence, Crypto currency, Token and Biz chain for user defined data"
		
  zh_CN "1、超块链核心协议栈
  2、应用层接口：
     命令行工具，
     RESTful接口，
     RPC接口
  3、系统模块：
    数字内容存在性证明，
    加密货币，
    加密通证，
    自定义业务区块链"
  )
 
cpack_add_component(${CORECOMPONET} FORCED_INSTALLATION
    DISPLAY_NAME "${APPLICATION_DISPLAY_SHORTNAME} Core"
    DESCRIPTION ${Paralism_Core_Desc}
	INSTALL_TYPES Full
	)

cpack_ifw_configure_component(${CORECOMPONET}
	DESCRIPTION zh_CN ${Paralism_Core_Desc}
	)

cpack_ifw_configure_component(${CORECOMPONET}
    SCRIPT "${CMAKE_SOURCE_DIR}/installscript.qs"
	)
	
cpack_ifw_configure_component(${CORECOMPONET}
    USER_INTERFACES "${CMAKE_SOURCE_DIR}/targetselectwidget.ui"
	)
	
if(PACK_GUI)
set(Paralism_GUI_Desc "GUI for ${APPLICATION_DISPLAY_SHORTNAME} Core"
				zh_CN "${APPLICATION_DISPLAY_SHORTNAME}客户端图形界面")
				
cpack_add_component(${GUICOMPONET}
    DISPLAY_NAME "${APPLICATION_DISPLAY_SHORTNAME}-qt"
    DESCRIPTION ${Paralism_GUI_Desc}
	INSTALL_TYPES Full
	)

cpack_ifw_configure_component(${GUICOMPONET}
	DESCRIPTION zh_CN ${Paralism_GUI_Desc}
	)
	
cpack_ifw_configure_component(${GUICOMPONET}
    SCRIPT "${CMAKE_SOURCE_DIR}/installscript-gui.qs"
	)
endif()	
	 
#cpack_ifw_configure_component(${CORECOMPONET}
#	LICENSES "The Hyperchain Company MIT" "${CMAKE_SOURCE_DIR}/LICENSE"
#	)

install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION bin COMPONENT ${CORECOMPONET})

#HC: Aleth http service
install(DIRECTORY dependencies/release/scripts/ DESTINATION bin/scripts COMPONENT ${CORECOMPONET})
if(WIN32)
	install(DIRECTORY dependencies/release/win32/core/ DESTINATION bin COMPONENT ${CORECOMPONET})
	
	if(PACK_GUI)
	    install(DIRECTORY dependencies/release/win32/gui/ DESTINATION gui COMPONENT ${GUICOMPONET})
	endif()
	
elseif(APPLE)
	install(DIRECTORY dependencies/release/apple/ DESTINATION bin COMPONENT ${CORECOMPONET})
	
elseif(UNIX)
	install(DIRECTORY conf/ DESTINATION bin 
		FILE_PERMISSIONS OWNER_READ GROUP_READ WORLD_READ OWNER_WRITE GROUP_WRITE WORLD_WRITE 
		DIRECTORY_PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE OWNER_WRITE GROUP_WRITE WORLD_WRITE
		COMPONENT ${CORECOMPONET} 
		PATTERN "hyperchain" PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
		)
	install(DIRECTORY dependencies/release/linux/core/ DESTINATION bin 
		FILE_PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE 
		DIRECTORY_PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE OWNER_WRITE GROUP_WRITE WORLD_WRITE
		COMPONENT ${CORECOMPONET})
		
    if(PACK_GUI)
	    install(DIRECTORY dependencies/release/linux/gui/ DESTINATION gui 
	        FILE_PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE 
		    DIRECTORY_PERMISSIONS OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE OWNER_WRITE GROUP_WRITE WORLD_WRITE
		    COMPONENT ${GUICOMPONET}
		    PATTERN "resources/*" PERMISSIONS OWNER_READ GROUP_READ WORLD_READ 
		    PATTERN "translations/*" PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
		    PATTERN "plugins/*" PERMISSIONS OWNER_READ GROUP_READ WORLD_READ
		    PATTERN "qt.conf" PERMISSIONS OWNER_READ GROUP_READ WORLD_READ )
    endif()	
	
	install(FILES logo.ico DESTINATION bin PERMISSIONS OWNER_READ GROUP_READ WORLD_READ COMPONENT ${CORECOMPONET})
endif()

	

