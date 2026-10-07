$(document).ready(function () {
    $("#postComment").on("click", function () {
        var commentInput = $("#commentInput").val();
        $.ajax({
            type: 'POST',
            url: 'CrossSiteScriptingStored/stored-xss',
            data: JSON.stringify({text: commentInput}),
            contentType: "application/json",
            dataType: 'json'
        }).then(
            function () {
                getChallenges();
                $("#commentInput").val('');
            }
        )
    })

    getChallenges();

    function getChallenges() {
        $("#list").empty();
        $.get('CrossSiteScriptingStored/stored-xss', function (result, status) {
            for (var i = 0; i < result.length; i++) {
                var li = $("<li>").addClass("comment");
                var pullLeft = $("<div>").addClass("pull-left");
                pullLeft.append($("<img>").addClass("avatar").attr("src", "images/avatar1.png").attr("alt", "avatar"));
                var body = $("<div>").addClass("comment-body");
                var heading = $("<div>").addClass("comment-heading");
                heading.append($("<h4>").addClass("user").text(result[i].user));
                heading.append($("<h5>").addClass("time").text(result[i].dateTime));
                body.append(heading);
                body.append($("<p>").text(result[i].text));
                li.append(pullLeft).append(body);
                $("#list").append(li);
            }

        });
    }
})
