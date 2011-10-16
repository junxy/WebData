<%@ Page Title="" Language="C#" MasterPageFile="~/Views/Shared/Site.Master" Inherits="System.Web.Mvc.ViewPage<PhotoGallery.Core.Gallery>" %>

<asp:Content ID="Content1" ContentPlaceHolderID="MainContent" runat="server">
    <h1>
        新建库</h1>
    <% using (Html.BeginForm())
       { %>
    <fieldset>
        <legend>新建库</legend>
        <ol>
            <li>
                <%= Html.LabelFor(m => m.Name) %>
                <%= Html.TextBoxFor(m => m.Name, new { title = "库名称", placeholder = "Gallery name" }) %>
                <%= Html.ValidationMessageFor(m => m.Name) %>
            </li>
        </ol>
        <p class="form-actions">
            <input type="submit" value="创建" title="创建库" />
            <a href="<%= Url.Action("Index") %>" title="返回库">取消</a>
        </p>
    </fieldset>
    <%} %>
</asp:Content>
<asp:Content ID="Content2" ContentPlaceHolderID="Title" runat="server">
    新建库
</asp:Content>