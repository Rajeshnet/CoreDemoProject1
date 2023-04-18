1. Core
The Core Layers will never depend on any other layer. Therefore what we do is that we create interfaces in the 
Application Layer and these interfaces get implemented in the external layers. This is also known and DIP or 
Dependency Inversion Principle.

1.1 Domain
All the Entities and the most common models are available here. Note that this Layer will NEVER depend on 
anything else.

1.2 Application
Interfaces, CQRS Features, Exceptions, Behaviors are available here.

2. Infrastructure
Whenever there is a requirement to communicate with an external source, we implement it on the Infrastructure 
Layer. For example, Database or other Services will be included here. To make the separation more visible, 
We will maintain further sub projects with the naming convention as ‘Infrastructure.xxxxxx’ 
where xxxxxx is the actual Point of Concern.

2.1 Infrastructure.Identity
In this implementation, we will make use of the already AWESOME Microsoft Identity. Let’s seperate the 
User Managment Database from the Main Application Database. This is made possible by 
multiple – DbContext Classes in each of the required Infrastructure Project

2.2 Infrastructure.Persistence
An Application Specific Database will be maintained. This is to ensure that there is no relation between 
the DBContext classes of Application and the Identity.

2.3 Infrastructure.Shared
Now, there are some services that are common to the other Infrastructure Layers and has the possibility 
of use in nearly all the Infrastructure Layers. This includes Mail Service, Date Time Service and so on. 
Thus it is a better Idea to have a shared Infrastructure project as well.

3. WebApi
This is also known as the Presentation Layer, where you would put in the project that the user 
can interact with. In our case it is the WebAPI Project.
