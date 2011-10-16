<%@ Page Title="" Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<IEnumerable<PhotoGallery.Core.Gallery>>" %>

<asp:Content ID="Content2" ContentPlaceHolderID="Title" runat="server">
    照片库
</asp:Content>
<asp:Content ID="Content1" ContentPlaceHolderID="MainContent" runat="server">
    <h1>
        库</h1>
    <% if (Model.Count() == 1)
       { %>
    <p>
        有一个库。</p>
    <%}
       else
       { %>
    <p>
        有
        <%= Model.Count() %>
        个库。</p>
    <%} %>
    <ul class="thumbnails gallery">
        <% foreach (var gallery in Model)
           {%>
        <li class="gallery"><a href="<%= Url.Action("View", "Gallery", new { id = gallery.Id }) %>">
            <img alt="来自 <%= gallery.Name %> 的图像" src="<%= Url.Action("Thumbnail", "Gallery", new { id = gallery.Id }) %>" class="thumbnail-no-border" />
            <span class="below-image">
                <%= gallery.Name %></span> <span class="image-overlay">
                    <%= gallery.PhotoCount %>
                    张照片</span> </a></li>
        <% } %>
    </ul>
    <p class="actions">
        <% if (this.Page.User.Identity.IsAuthenticated)
           { %>
        <%= Html.ActionLink("新建库", "New", "Gallery") %>
        <%} %>
    </p>
</asp:Content>