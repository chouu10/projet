angular.module('MyApp')
    .controller('AdminCtrl', ['$scope', 'adminis',  function ($scope, adminis) {

        $scope.admin = function () {
            adminis.admin({
                categorie: $scope.categorie,
                question: $scope.question
                 });
        };
        $scope.pageClass = 'fadeZoom'
    }]);